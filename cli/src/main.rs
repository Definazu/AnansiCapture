use anansi_core::{
    capture::{CaptureConfig, CaptureMode, FilterConfig},
    observers::Observer,
    AnansiFacade,
};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashSet;

#[derive(Parser)]
#[command(name = "anansi")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start capturing traffic
    Capture {
        /// Network interface name
        #[arg(short = 'I', long)]
        interface: String,

        /// Ports filter (e.g. 80,443,1000-2000)
        #[arg(short = 'p', long)]
        ports: Option<String>,

        /// Protocols filter (comma-separated)
        #[arg(long)]
        protocols: Option<String>,

        /// Capture mode
        #[arg(short = 'm', long, default_value = "promiscuous")]
        mode: CaptureModeArg,

        /// Do not parse packets
        #[arg(long)]
        no_parse: bool,
    },
    /// List available interfaces
    List,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum CaptureModeArg {
    Promiscuous,
    Filtered,
}

impl From<CaptureModeArg> for CaptureMode {
    fn from(value: CaptureModeArg) -> Self {
        match value {
            CaptureModeArg::Promiscuous => CaptureMode::Promiscuous,
            CaptureModeArg::Filtered => CaptureMode::Filtered(FilterConfig::default()),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture {
            interface,
            ports,
            protocols,
            mode,
            no_parse,
        } => {
            let mut filter_config = FilterConfig::default();
            
            // Parse ports
            if let Some(ports_str) = ports {
                filter_config.ports = parse_ports(&ports_str)?;
            }

            // Parse protocols
            if let Some(proto_str) = protocols {
                filter_config.protocols = Some(
                    proto_str
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .collect(),
                );
            }

            let config = CaptureConfig {
                interface,
                mode: match mode.into() {
                    CaptureMode::Filtered(_) => CaptureMode::Filtered(filter_config),
                    other => other,
                },
                buffer_size: 1024,
                parse_packets: !no_parse,
                snapshot_length: 65535,
                read_timeout: 1000,
            };

            let facade = AnansiFacade::new(config);
            
            // Добавляем консольный observer
            facade.add_observer(ConsoleObserver::new()).await;
            
            facade.start_capture().await?;
            
            // Бесконечное ожидание (в реальности можно добавить обработку сигналов)
            tokio::signal::ctrl_c().await?;
            facade.stop_capture().await?;
        }
        Commands::List => {
            let facade = AnansiFacade::new(CaptureConfig::default());
            let interfaces = facade.get_interfaces().await?;
            println!("Available interfaces:");
            for iface in interfaces {
                println!("  - {}", iface);
            }
        }
    }

    Ok(())
}

fn parse_ports(input: &str) -> anyhow::Result<Option<HashSet<u16>>> {
    if input == "-" {
        return Ok(None);
    }

    let mut ports = HashSet::new();
    for part in input.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow::anyhow!("Invalid port range: {}", part));
            }
            let start = range[0].parse::<u16>()?;
            let end = range[1].parse::<u16>()?;
            for port in start..=end {
                ports.insert(port);
            }
        } else {
            ports.insert(part.parse::<u16>()?);
        }
    }
    Ok(Some(ports))
}

// Реализация ConsoleObserver
struct ConsoleObserver;

impl ConsoleObserver {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Observer for ConsoleObserver {
    async fn update(&self, packet: &anansi_core::Packet) {
        if let Some(data) = &packet.parsed_data {
            println!(
                "[{}] {} → {} | {} ({} bytes)",
                packet.interface, data.source, data.destination, 
                data.protocol, data.size
            );
        } else {
            println!(
                "[{}] Raw packet ({} bytes)",
                packet.interface, 
                packet.raw_data.len()
            );
        }
    }
}