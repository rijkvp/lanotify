use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let config = Config {
        scan_interval: Duration::from_secs(10),
        device_map: HashMap::from([
            (MacAddr::new("00:11:22:33:44:55"), "My Laptop".to_string()),
            (MacAddr::new("AA:BB:CC:DD:EE:FF"), "My Phone".to_string()),
        ]),
    };

    Daemon::new(config).run()?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

struct Config {
    scan_interval: Duration,
    device_map: HashMap<MacAddr, String>,
}

#[derive(Debug, Clone)]
struct DeviceState {
    device: Device,
    last_seen: DateTime<Local>,
    is_connected: bool,
    activity: Vec<bool>,
}

impl DeviceState {
    fn new(device: Device) -> Self {
        DeviceState {
            device,
            last_seen: Local::now(),
            is_connected: true,
            activity: vec![true],
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
        write!(f, " ")?;
        for act in &self.activity {
            write!(f, "{}", if *act { "X" } else { "O" })?;
        }
        write!(f, "\t{}", self.last_seen.format("%Y-%m-%d %H:%M:%S"))?;
        write!(f, "\t{}", self.device)?;
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
            log::info!("Scanning network...");

            let devices = arp_scan()?;

            self.update_state(devices);
            self.log_state();

            log::info!("Waiting {:?} until next scan...", self.config.scan_interval);
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
        for state in self.state.values_mut() {
            if !new_devices.iter().any(|d| d.mac == state.device.mac) {
                log::info!("Device disconnected: {}", state.device);
                state.activity.push(false);
            }
        }
        for device in new_devices {
            match self.state.entry(device.mac.clone()) {
                Entry::Occupied(mut e) => {
                    let state = e.get_mut();
                    state.device = device;
                    state.last_seen = Local::now();
                    state.activity.push(true);
                }
                Entry::Vacant(e) => {
                    log::info!("New device detected: {device}");
                    e.insert(DeviceState::new(device));
                }
            }
        }
    }

    fn log_state(&self) {
        let mut mapping: Vec<(MacAddr, DeviceState)> = self.state.clone().into_iter().collect();
        mapping.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, state) in mapping {
            println!("{state}");
        }
    }
}

fn arp_scan() -> Result<Vec<Device>> {
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
