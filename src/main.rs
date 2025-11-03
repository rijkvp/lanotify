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
const OFFLINE_THRESHOLD: usize = 10;
const RECENT_WINDOW: usize = 5;

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
    ping_history: ScanHistory,
}

#[derive(Debug, Clone)]
struct ScanHistory {
    log: VecDeque<bool>,
}

impl ScanHistory {
    fn new() -> Self {
        Self {
            log: VecDeque::new(),
        }
    }

    #[cfg(test)]
    fn from(array: Vec<bool>) -> Self {
        assert_eq!(array.len(), HISTORY_SIZE);
        Self {
            log: VecDeque::from(array),
        }
    }

    fn update(&mut self, state: bool) {
        self.log.push_front(state);
        if self.log.len() > HISTORY_SIZE {
            self.log.pop_back();
        }
    }

    // Determines statistically if the device is likely to be connected or disconnected
    // Takes in the current connection state
    fn is_connected(&self, is_connected: bool) -> bool {
        if self.log.len() < OFFLINE_THRESHOLD {
            // Insufficient data
            return is_connected;
        }

        let last_ping = self.log.iter().position(|v| *v).unwrap_or(HISTORY_SIZE);
        let base_rate =
            self.log.iter().map(|v| *v as u64).sum::<u64>() as f64 / self.log.len() as f64;
        if base_rate <= 0.3 {
            // Devices that are sleeping a lot, or a device that has just gone offline!
            if last_ping >= HISTORY_SIZE {
                false
            } else if last_ping < RECENT_WINDOW {
                true
            } else {
                is_connected
            }
        } else if base_rate <= 0.5 {
            // Intermittent devices
            if last_ping > OFFLINE_THRESHOLD {
                false
            } else {
                true
            }
        } else {
            // Always-on devices devices
            let recent_rate = self
                .log
                .iter()
                .take(RECENT_WINDOW)
                .map(|v| *v as u64)
                .sum::<u64>() as f64
                / RECENT_WINDOW as f64;
            let deviation_ratio = (recent_rate - base_rate) / (base_rate + 0.01);

            if is_connected && deviation_ratio < -0.6 && !self.log.front().unwrap() {
                false
            } else {
                is_connected
            }
        }
    }
}

impl Display for ScanHistory {
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
            ping_history: ScanHistory::new(),
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
            if state.ping_history.is_connected(state.is_connected) {
                if !state.is_connected {
                    state.is_connected = true;
                    notifications.push((state.device.clone(), true));
                }
            } else {
                if state.is_connected {
                    state.is_connected = false;
                    notifications.push((state.device.clone(), false));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connected_always_on() {
        let mut history = ScanHistory::from(vec![true; HISTORY_SIZE]);
        let mut is_connected = true;

        // for a short while it stays connected
        for _ in 0..3 {
            history.update(false);
            is_connected = history.is_connected(is_connected);
            assert!(is_connected);
        }

        // stay disconnected
        for _ in 0..HISTORY_SIZE {
            history.update(false);
            is_connected = history.is_connected(is_connected);
            assert!(!is_connected);
        }
    }

    #[test]
    fn test_connected_always_on_temporary_offline() {
        let mut history = ScanHistory::from(vec![true; HISTORY_SIZE]);

        // 3x scan misses
        for _ in 0..3 {
            history.update(false);
        }

        let mut is_connected = true;

        // stay connected
        for _ in 0..HISTORY_SIZE {
            is_connected = history.is_connected(is_connected);
            assert!(is_connected);
            history.update(true);
        }
    }

    #[test]
    fn test_connected_sleeping() {
        let mut history = ScanHistory::new();
        for i in 0..HISTORY_SIZE {
            history.update(i % 10 == 0); // 10% activity
        }

        let mut is_connected = true;
        is_connected = history.is_connected(is_connected);
        assert!(is_connected);

        // stays connected the entire time
        for _ in 0..HISTORY_SIZE {
            history.update(false);
            assert!(is_connected);
        }

        is_connected = history.is_connected(is_connected);
        assert!(!is_connected);
    }

    #[test]
    fn test_connected_intermittent() {
        let mut history = ScanHistory::new();
        let mut is_connected = true;
        for i in 0..HISTORY_SIZE {
            is_connected = history.is_connected(is_connected);
            assert!(is_connected);
            history.update(i % 2 == 0); // 50% activity
        }
        for _ in 0..OFFLINE_THRESHOLD {
            history.update(false);
        }
        for _ in 0..HISTORY_SIZE {
            is_connected = history.is_connected(is_connected);
            assert!(!is_connected);
            history.update(false);
        }
    }

    #[test]
    fn test_connected_new_sleeping() {
        let mut is_connected = true;
        let mut history = ScanHistory::new();
        for i in 0..(HISTORY_SIZE * 2) {
            is_connected = history.is_connected(is_connected);
            assert!(is_connected);
            history.update(i % 20 == 0); // very low activity
        }
    }

    #[test]
    fn test_connected_intervals() {
        // on and off in intervals
        for x in 1..RECENT_WINDOW {
            let mut is_connected = true;
            let mut history = ScanHistory::new();
            for y in 0..HISTORY_SIZE {
                for z in 0..OFFLINE_THRESHOLD {
                    // offset of z
                    for _ in 0..z {
                        history.update(false);
                    }
                    // x times on
                    for _ in 0..x {
                        is_connected = history.is_connected(is_connected);
                        assert!(is_connected, "x={x}, y={y}, z={z}, {history}");
                        history.update(true);
                    }
                    // x times off
                    for _ in 0..x {
                        is_connected = history.is_connected(is_connected);
                        assert!(is_connected, "x={x}, y={y}, z={z} {history}");
                        history.update(false);
                    }
                }
            }
        }
    }
}
