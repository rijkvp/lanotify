use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use notify_rust::Notification;
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
struct Config {
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    scan_interval: Duration,
    devices: HashMap<MacAddr, String>,
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
    activity: ActivityLog,
}

const ACTIVITY_LOG_SIZE: usize = 5;
const CONNECTED_N: usize = 3;

#[derive(Debug, Clone)]
struct ActivityLog {
    log: VecDeque<bool>,
}

enum ConnectionStatus {
    Unsure,
    Connected,
    Disconnected,
}

impl ActivityLog {
    fn with_initial(state: bool) -> Self {
        let mut log = VecDeque::with_capacity(ACTIVITY_LOG_SIZE);
        for _ in 0..ACTIVITY_LOG_SIZE {
            log.push_back(state);
        }
        Self { log }
    }

    fn log(&mut self, state: bool) {
        if self.log.len() == ACTIVITY_LOG_SIZE {
            self.log.pop_front();
        }
        self.log.push_back(state);
    }

    fn connection_status(&self) -> ConnectionStatus {
        let first = self.log[ACTIVITY_LOG_SIZE - CONNECTED_N];
        for i in ACTIVITY_LOG_SIZE - CONNECTED_N + 1..ACTIVITY_LOG_SIZE {
            if self.log[i] != first {
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

impl Display for ActivityLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for act in &self.log {
            write!(f, "{}", if *act { "O" } else { "-" })?;
        }
        Ok(())
    }
}

impl DeviceState {
    fn new(device: Device, assume_connected: bool) -> Self {
        DeviceState {
            device,
            last_seen: Local::now(),
            is_connected: assume_connected,
            activity: ActivityLog::with_initial(assume_connected),
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
            self.activity,
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
            self.state
                .insert(device.mac.clone(), DeviceState::new(device, true));
        }
        log::info!("Initilized with {} devices", self.state.len());
    }

    fn update_state(&mut self, new_devices: Vec<Device>) {
        for device in &new_devices {
            match self.state.entry(device.mac.clone()) {
                Entry::Occupied(mut e) => {
                    let state = e.get_mut();
                    state.device = device.clone();
                    state.last_seen = Local::now();
                    state.activity.log(true);
                }
                Entry::Vacant(e) => {
                    e.insert(DeviceState::new(device.clone(), false));
                }
            }
        }
        let mut notifications = Vec::new();
        for state in self.state.values_mut() {
            if !new_devices.iter().any(|d| d.mac == state.device.mac) {
                state.activity.log(false);
            }
            match state.activity.connection_status() {
                ConnectionStatus::Connected => {
                    if !state.is_connected {
                        state.is_connected = true;
                        notifications.push((state.device.clone(), true));
                    }
                }
                ConnectionStatus::Disconnected => {
                    if state.is_connected {
                        state.is_connected = false;
                        log::info!("Device disconnected: {}", state.device);
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
        if let Some(name) = self.config.devices.get(&device.mac) {
            let status = if state { "connected" } else { "disconnected" };
            Notification::new()
                .summary(&format!("Device {} {}", name, status))
                .body(&format!(
                    "Device {} with IP {} and MAC {} is {}",
                    name, device.ip, device.mac.0, status
                ))
                .show()?;
        }
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
