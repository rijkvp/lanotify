use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use serde::Deserialize;
use serde_with::serde_as;
use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    fmt::{Display, Write},
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::Duration,
};

const HISTORY_SIZE: usize = 30;
const RECENT_SIZE: usize = 10;

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let config_path = if let Some(arg) = std::env::args().skip(1).next() {
        PathBuf::from(arg)
    } else {
        PathBuf::from("config.toml")
    };
    log::info!("loading config from '{}'", config_path.display());

    let config = Config::load(&config_path).context("Failed to load config file")?;

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

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    scan_interval: Duration,
    devices: HashMap<MacAddr, String>,
    ntfy_url: String,
    notify_unknown: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan_interval: Duration::from_secs(10),
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
    ping_history: PingHistory,
}

#[derive(Debug, Clone)]
struct PingHistory {
    log: VecDeque<bool>,
}

enum DeviceStatus {
    Online,
    Offline,
}

impl PingHistory {
    fn new() -> Self {
        Self {
            log: VecDeque::new(),
        }
    }

    fn update(&mut self, state: bool) {
        self.log.push_front(state);
        if self.log.len() > HISTORY_SIZE {
            self.log.pop_back();
        }
    }

    fn connection_status(&self, is_connected: bool) -> DeviceStatus {
        if self.log.len() < HISTORY_SIZE {
            return if is_connected {
                DeviceStatus::Online
            } else {
                DeviceStatus::Offline
            };
        }

        let last_ping = self.log.iter().position(|v| *v).unwrap_or(HISTORY_SIZE);
        let base_rate =
            self.log.iter().map(|v| *v as u64).sum::<u64>() as f64 / self.log.len() as f64;
        if base_rate <= 0.3 {
            // devices that are sleeping a lot
            if last_ping >= HISTORY_SIZE {
                DeviceStatus::Offline
            } else {
                DeviceStatus::Online
            }
        } else if base_rate < 0.8 {
            // devices that are sleeping frequently
            if last_ping >= HISTORY_SIZE / 2 {
                DeviceStatus::Offline
            } else {
                DeviceStatus::Online
            }
        } else {
            // always-on devices
            let recent_rate = self
                .log
                .iter()
                .take(RECENT_SIZE)
                .map(|v| *v as u64)
                .sum::<u64>() as f64
                / RECENT_SIZE as f64;
            let deviation_ratio = (recent_rate - base_rate) / (base_rate + 0.01);
            if deviation_ratio < -0.6 && recent_rate < 0.3 || last_ping > RECENT_SIZE {
                DeviceStatus::Offline
            } else {
                DeviceStatus::Online
            }
        }
    }
}

impl Display for PingHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for act in &self.log {
            f.write_char(if *act { 'O' } else { '-' })?;
        }
        for _ in 0..(HISTORY_SIZE - self.log.len()) {
            f.write_char('.')?;
        }
        Ok(())
    }
}

impl DeviceState {
    fn new(device: Device) -> Self {
        DeviceState {
            device,
            last_seen: Local::now(),
            is_connected: true, // assume connected at first
            ping_history: PingHistory::new(),
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
            "  {}  {}  {}  {:15}",
            self.ping_history,
            self.last_seen.format("%Y-%m-%d %H:%M:%S"),
            self.device.mac.0,
            self.device.ip,
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
                .insert(device.mac.clone(), DeviceState::new(device));
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
                    state.ping_history.update(true);
                }
                // found a new device
                Entry::Vacant(e) => {
                    e.insert(DeviceState::new(device.clone()));
                    notifications.push((device.clone(), true));
                }
            }
        }
        for state in self.state.values_mut() {
            // if the device was not found in the new scan, update its log to disconnected
            if !new_devices.iter().any(|d| d.mac == state.device.mac) {
                state.ping_history.update(false);
            }
            match state.ping_history.connection_status(state.is_connected) {
                DeviceStatus::Online => {
                    if !state.is_connected {
                        state.is_connected = true;
                        notifications.push((state.device.clone(), true));
                    }
                }
                DeviceStatus::Offline => {
                    if state.is_connected {
                        state.is_connected = false;
                        notifications.push((state.device.clone(), false));
                    }
                }
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
        mapping.sort_by_key(|(_, s)| {
            let name = self.config.devices.get(&s.device.mac);
            (name.is_none(), name.cloned())
        });
        println!("Status of {} devices:", mapping.len());
        for (_, state) in mapping {
            print!("{state}  ");
            if let Some(name) = self.config.devices.get(&state.device.mac) {
                print!("{name}");
            } else {
                print!("Unknown: {}", state.device.vendor);
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

        let name = self.config.devices.get(&device.mac);
        let priority = if name.is_some() { "default" } else { "high" };
        let display_name = name
            .map(|d| d.to_string())
            .unwrap_or(format!("Unknown {}", &device.vendor));
        let title = format!("Device {} {}", display_name, status);
        let body = format!(
            "Device {} with IP {} and MAC {} is {}",
            display_name, device.ip, device.mac.0, status
        );
        log::info!("[notify] {title} {body}");
        let resp = ureq::post(&self.config.ntfy_url)
            .header("Title", &title)
            .header("X-Priority", priority)
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
