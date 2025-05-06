use anansi_core::AnansiFacade;
use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{info, debug, warn};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List available network interfaces
    ListInterfaces,
    /// Start packet capture
    Capture {
        /// Network interface to capture from
        #[arg(short, long)]
        interface: String,
        /// Filter expression (BPF syntax)
        #[arg(short, long)]
        filter: Option<String>,
        /// Enable debug mode
        #[arg(short, long)]
        debug: bool,
        /// Output file for PCAP capture
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    let facade = Arc::new(Mutex::new(AnansiFacade::new(cli.command.is_debug())));

    match cli.command {
        Commands::ListInterfaces => {
            let interfaces = facade.lock().await.list_interfaces().await?;
            println!("{}", interfaces);
        }
        Commands::Capture { interface, filter, debug: _, output } => {
            let facade_clone = facade.clone();
            let observer = Arc::new(PrintObserver::new(facade_clone));
            facade.lock().await.add_observer(observer).await;

            // Set up PCAP output if specified
            if let Some(output_file) = &output {
                info!("Saving capture to PCAP file: {}", output_file);
                facade.lock().await.set_pcap_output(output_file).await?;
            }

            info!("Starting capture on interface: {}", interface);
            if let Some(filter) = &filter {
                info!("Using filter: {}", filter);
            }

            facade.lock().await.start_capture(&interface, filter.as_deref()).await?;

            // Wait for Ctrl+C
            tokio::signal::ctrl_c().await?;
            facade.lock().await.stop_capture().await;
        }
    }

    Ok(())
}

struct PrintObserver {
    facade: Arc<Mutex<AnansiFacade>>,
}

impl PrintObserver {
    fn new(facade: Arc<Mutex<AnansiFacade>>) -> Self {
        Self { facade }
    }
}

#[async_trait::async_trait]
impl anansi_core::Observer for PrintObserver {
    async fn update<'a>(&self, packet: &'a pcap::Packet<'a>) {
        let facade = self.facade.lock().await;
        let info = facade.process_packet(packet);
        println!("{}", facade.format_packet_info(&info));
    }
}

trait CommandExt {
    fn is_debug(&self) -> bool;
}

impl CommandExt for Commands {
    fn is_debug(&self) -> bool {
        match self {
            Commands::ListInterfaces => false,
            Commands::Capture { debug, .. } => *debug,
        }
    }
}
