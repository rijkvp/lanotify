use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use serde::Deserialize;
use serde_with::serde_as;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let config = Config::load(Path::new("config.toml")).context("Failed to load config file")?;
    log::info!("Loaded config: {:#?}", config);

    Daemon::new(config).run()?;

    Ok(())
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
struct MacAddr(String);

impl MacAddr {
    fn new(mac: &str) -> Self {
        if mac.len() != 17 {
            panic!("Invalid MAC address length");
        }
        Self(mac.to_string())
    }
}

#[derive(Debug, Clone)]
struct Device {
    mac: MacAddr,
    ip: Ipv4Addr,
    vendor: String,
}

impl Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\t{}\t{}", self.mac.0, self.ip, self.vendor)
    }
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    scan_interval: Duration,
    devices: HashMap<MacAddr, String>,
    history_size: usize,
    ntfy_url: String,
    notify_unknown: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan_interval: Duration::from_secs(10),
            history_size: 5,
            devices: HashMap::new(),
            ntfy_url: "http://localhost:8080/notify".to_string(),
            notify_unknown: true,
        }
    }
}

impl Config {
    fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path).context("Failed to read config file")?;
        let config: Config = toml::from_str(&contents).context("Failed to parse config file")?;
        Ok(config)
    }
}

#[derive(Debug, Clone)]
struct DeviceState {
    device: Device,
    last_seen: DateTime<Local>,
    is_connected: bool,
    status_log: StatusLog,
}

#[derive(Debug, Clone)]
struct StatusLog {
    log: VecDeque<bool>,
}

enum ConnectionStatus {
    Unsure,
    Connected,
    Disconnected,
}

impl StatusLog {
    fn new(initial: bool, size: usize) -> Self {
        Self {
            log: VecDeque::from(vec![initial; size]),
        }
    }

    fn update(&mut self, state: bool) {
        self.log.pop_front();
        self.log.push_back(state);
    }

    fn connection_status(&self) -> ConnectionStatus {
        let first = self.log.front().copied().unwrap_or(false);
        for value in self.log.iter().copied().skip(1) {
            if value != first {
                // if not all the same
                return ConnectionStatus::Unsure;
            }
        }
        if first {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        }
    }
}

impl Display for StatusLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for act in &self.log {
            write!(f, "{}", if *act { "O" } else { "-" })?;
        }
        Ok(())
    }
}

impl DeviceState {
    fn new(device: Device, history_size: usize) -> Self {
        DeviceState {
            device,
            last_seen: Local::now(),
            is_connected: true, // assume connected at first
            status_log: StatusLog::new(true, history_size),
        }
    }
}

impl Display for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_connected {
            write!(f, "✅")?;
        } else {
            write!(f, "❌")?;
        };
        write!(
            f,
            " \t{}\t{}\t{}",
            self.status_log,
            self.last_seen.format("%Y-%m-%d %H:%M:%S"),
            self.device
        )?;
        Ok(())
    }
}

struct Daemon {
    config: Config,
    state: HashMap<MacAddr, DeviceState>,
}

impl Daemon {
    fn new(config: Config) -> Self {
        Self {
            config,
            state: HashMap::new(),
        }
    }

    fn run(&mut self) -> Result<()> {
        let devices = arp_scan()?; // initial scan
        self.init_state(devices);
        self.log_state();
        loop {
            let devices = arp_scan()?;

            self.update_state(devices);
            self.log_state();

            log::debug!("Waiting {:?} until next scan...", self.config.scan_interval);
            sleep(self.config.scan_interval);
        }
    }

    fn init_state(&mut self, devices: Vec<Device>) {
        for device in devices {
            self.state.insert(
                device.mac.clone(),
                DeviceState::new(device, self.config.history_size),
            );
        }
        log::info!("Initilized with {} devices", self.state.len());
    }

    fn update_state(&mut self, new_devices: Vec<Device>) {
        let mut notifications = Vec::new();
        for device in &new_devices {
            match self.state.entry(device.mac.clone()) {
                // update status existing device
                Entry::Occupied(mut e) => {
                    let state = e.get_mut();
                    state.device = device.clone();
                    state.last_seen = Local::now();
                    state.status_log.update(true);
                }
                // found a new device
                Entry::Vacant(e) => {
                    e.insert(DeviceState::new(device.clone(), self.config.history_size));
                    notifications.push((device.clone(), true));
                }
            }
        }
        for state in self.state.values_mut() {
            // if the device was not found in the new scan, update its log to disconnected
            if !new_devices.iter().any(|d| d.mac == state.device.mac) {
                state.status_log.update(false);
            }
            match state.status_log.connection_status() {
                ConnectionStatus::Connected => {
                    if !state.is_connected {
                        state.is_connected = true;
                        notifications.push((state.device.clone(), true));
                    }
                }
                ConnectionStatus::Disconnected => {
                    if state.is_connected {
                        state.is_connected = false;
                        notifications.push((state.device.clone(), false));
                    }
                }
                ConnectionStatus::Unsure => {}
            }
        }
        for (device, state) in notifications {
            if let Err(e) = self.notify(&device, state) {
                log::error!("Failed to send notification: {}", e);
            }
        }
    }

    fn log_state(&self) {
        let mut mapping: Vec<(MacAddr, DeviceState)> = self.state.clone().into_iter().collect();
        mapping.sort_by(|a, b| a.0.cmp(&b.0));
        println!("Status of {} devices", mapping.len());
        for (_, state) in mapping {
            print!("{state}\t");
            if let Some(name) = self.config.devices.get(&state.device.mac) {
                print!(" {name}");
            } else {
                print!(" (unknown)");
            }
            println!();
        }
    }

    fn notify(&self, device: &Device, state: bool) -> Result<()> {
        let status = if state { "connected" } else { "disconnected" };
        if !self.config.notify_unknown && self.config.devices.get(&device.mac).is_none() {
            log::info!(
                "Unknown device {} with IP {} and MAC {} is {}",
                device.vendor,
                device.ip,
                device.mac.0,
                status
            );
            return Ok(());
        }

        let name = self
            .config
            .devices
            .get(&device.mac)
            .map(|d| d.to_string())
            .unwrap_or(format!("Unknown {}", &device.vendor));
        let title = format!("Device {} {}", name, status);
        let body = format!(
            "Device {} with IP {} and MAC {} is {}",
            name, device.ip, device.mac.0, status
        );
        log::info!("[notify] {title} {body}");
        let resp = ureq::post(&self.config.ntfy_url)
            .header("Title", &title)
            .send(body)?;
        println!("Notification sent: {} {:?}", resp.status(), resp.body());
        Ok(())
    }
}

fn arp_scan() -> Result<Vec<Device>> {
    log::debug!("starting network scan");
    let output = Command::new("arp-scan")
        .args([
            "--localnet",
            "--plain",
            "--format=${ip}\\t${mac}\\t${vendor}",
        ])
        .output()
        .context("Failed to execute 'arp-scan' command")?;

    let devices = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let mut fields = line.split('\t');
            let ip = fields.next().context("missing IP address")?;
            let mac = fields.next().context("missing MAC address")?;
            let vendor = fields.next().context("missing vendor")?;

            Ok(Device {
                mac: MacAddr::new(mac),
                ip: ip.parse::<Ipv4Addr>().context("invalid IP address")?,
                vendor: vendor.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(devices)
}
