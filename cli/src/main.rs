use anansi_core::AnansiFacade;
use clap::{Parser, ValueEnum};
use log::{info, error, debug, warn};
use std::process;
use anyhow::Result;
use std::sync::Arc;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::Packet;
use colored::*;
use chrono::Local;

#[derive(Debug, Clone, ValueEnum)]
enum PortRange {
    All,
    Range,
    List,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Сетевой интерфейс для захвата
    #[arg(short = 'I', long, default_value = "any")]
    interface: String,

    /// Диапазон портов для фильтрации
    /// Форматы:
    /// -p 1-1000 (диапазон)
    /// -p 80,443 (список)
    /// -p- (все порты)
    #[arg(short = 'p', long)]
    ports: Option<String>,

    /// Показать список доступных интерфейсов
    #[arg(long)]
    list_interfaces: bool,

    /// Включить promiscuous режим
    #[arg(short = 'P', long)]
    promiscuous: bool,

    /// Включить отладочный режим
    #[arg(long)]
    debug: bool,
}

struct PacketLogger {
    debug: bool,
}

impl anansi_core::capture::Observer for PacketLogger {
    fn update(&self, packet: &pcap::Packet) {
        if self.debug {
            debug!("Получен пакет размером {} байт", packet.len());
        }
        
        // Проверяем минимальный размер для Ethernet пакета
        if packet.len() < 14 {
            warn!("Пакет слишком мал для Ethernet: {} байт", packet.len());
            return;
        }

        match EthernetPacket::new(packet.data) {
            Some(ethernet) => {
                if self.debug {
                    debug!("Ethernet тип: {:?}", ethernet.get_ethertype());
                }
                
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            if self.debug {
                                debug!("IPv4 протокол: {:?}", ipv4.get_next_level_protocol());
                            }
                            
                            match ipv4.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
                                        let flags = format_tcp_flags(&tcp);
                                        println!("{} {} {}:{} > {}:{} {} {}",
                                            timestamp.blue(),
                                            "TCP".green(),
                                            ipv4.get_source().to_string().yellow(),
                                            tcp.get_source().to_string().cyan(),
                                            ipv4.get_destination().to_string().yellow(),
                                            tcp.get_destination().to_string().cyan(),
                                            flags,
                                            format!("{} bytes", packet.len()).magenta()
                                        );
                                    } else if self.debug {
                                        warn!("Не удалось разобрать TCP пакет");
                                    }
                                },
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
                                        println!("{} {} {}:{} > {}:{} {}",
                                            timestamp.blue(),
                                            "UDP".green(),
                                            ipv4.get_source().to_string().yellow(),
                                            udp.get_source().to_string().cyan(),
                                            ipv4.get_destination().to_string().yellow(),
                                            udp.get_destination().to_string().cyan(),
                                            format!("{} bytes", packet.len()).magenta()
                                        );
                                    } else if self.debug {
                                        warn!("Не удалось разобрать UDP пакет");
                                    }
                                },
                                IpNextHeaderProtocols::Icmp => {
                                    if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                                        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
                                        println!("{} {} {} > {} {}",
                                            timestamp.blue(),
                                            "ICMP".green(),
                                            ipv4.get_source().to_string().yellow(),
                                            ipv4.get_destination().to_string().yellow(),
                                            format!("{} bytes", packet.len()).magenta()
                                        );
                                    } else if self.debug {
                                        warn!("Не удалось разобрать ICMP пакет");
                                    }
                                },
                                _ => if self.debug {
                                    debug!("IPv4: {} -> {}", 
                                        ipv4.get_source(),
                                        ipv4.get_destination());
                                },
                            }
                        } else if self.debug {
                            warn!("Не удалось разобрать IPv4 пакет");
                        }
                    },
                    EtherTypes::Ipv6 => {
                        if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                            if self.debug {
                                debug!("IPv6 протокол: {:?}", ipv6.get_next_header());
                            }
                            
                            match ipv6.get_next_header() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
                                        let flags = format_tcp_flags(&tcp);
                                        println!("{} {} [{}]:{} > [{}]:{} {} {}",
                                            timestamp.blue(),
                                            "TCP".green(),
                                            ipv6.get_source().to_string().yellow(),
                                            tcp.get_source().to_string().cyan(),
                                            ipv6.get_destination().to_string().yellow(),
                                            tcp.get_destination().to_string().cyan(),
                                            flags,
                                            format!("{} bytes", packet.len()).magenta()
                                        );
                                    } else if self.debug {
                                        warn!("Не удалось разобрать TCP пакет");
                                    }
                                },
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
                                        println!("{} {} [{}]:{} > [{}]:{} {}",
                                            timestamp.blue(),
                                            "UDP".green(),
                                            ipv6.get_source().to_string().yellow(),
                                            udp.get_source().to_string().cyan(),
                                            ipv6.get_destination().to_string().yellow(),
                                            udp.get_destination().to_string().cyan(),
                                            format!("{} bytes", packet.len()).magenta()
                                        );
                                    } else if self.debug {
                                        warn!("Не удалось разобрать UDP пакет");
                                    }
                                },
                                IpNextHeaderProtocols::Icmpv6 => {
                                    if let Some(icmpv6) = Icmpv6Packet::new(ipv6.payload()) {
                                        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
                                        println!("{} {} [{}] > [{}] {}",
                                            timestamp.blue(),
                                            "ICMPv6".green(),
                                            ipv6.get_source().to_string().yellow(),
                                            ipv6.get_destination().to_string().yellow(),
                                            format!("{} bytes", packet.len()).magenta()
                                        );
                                    } else if self.debug {
                                        warn!("Не удалось разобрать ICMPv6 пакет");
                                    }
                                },
                                _ => if self.debug {
                                    debug!("IPv6: [{}] -> [{}]", 
                                        ipv6.get_source(),
                                        ipv6.get_destination());
                                },
                            }
                        } else if self.debug {
                            warn!("Не удалось разобрать IPv6 пакет");
                        }
                    },
                    _ => if self.debug {
                        debug!("Ethernet: {} -> {}", 
                            ethernet.get_source(),
                            ethernet.get_destination());
                    },
                }
            },
            None => if self.debug {
                warn!("Не удалось разобрать Ethernet пакет");
                debug!("Сырые данные: {:?}", &packet.data[..std::cmp::min(32, packet.len())]);
            }
        }
    }
}

fn format_tcp_flags(tcp: &TcpPacket) -> String {
    let mut flags = String::new();
    let flags_byte = tcp.get_flags();
    if flags_byte & 0x02 != 0 { flags.push('S'); } // SYN
    if flags_byte & 0x10 != 0 { flags.push('A'); } // ACK
    if flags_byte & 0x01 != 0 { flags.push('F'); } // FIN
    if flags_byte & 0x04 != 0 { flags.push('R'); } // RST
    if flags_byte & 0x08 != 0 { flags.push('P'); } // PSH
    if flags_byte & 0x20 != 0 { flags.push('U'); } // URG
    if flags_byte & 0x40 != 0 { flags.push('E'); } // ECE
    if flags_byte & 0x80 != 0 { flags.push('C'); } // CWR
    flags.red().to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Настраиваем логирование
    let log_level = if cli.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .init();

    if cli.list_interfaces {
        list_interfaces()?;
        return Ok(());
    }

    let facade = AnansiFacade::new();
    let observer = Arc::new(PacketLogger { debug: cli.debug });
    let _observer_id = facade.add_observer(observer).await;

    let filter = create_filter(&cli)?;
    info!("Запуск захвата на интерфейсе: {}", cli.interface);
    info!("Фильтр: {}", filter.as_deref().unwrap_or("нет"));

    if let Err(e) = facade.start_capture(cli.promiscuous, filter.as_deref()).await {
        error!("Ошибка при запуске захвата: {}", e);
        process::exit(1);
    }

    // Ожидаем Ctrl+C
    tokio::signal::ctrl_c().await?;
    facade.stop_capture().await;
    info!("Захват остановлен");

    Ok(())
}

fn list_interfaces() -> Result<()> {
    let interfaces = pcap::Device::list()?;
    println!("{}", "Доступные интерфейсы:".bold().underline());
    for interface in interfaces {
        if let Some(desc) = interface.desc {
            println!("{} -> {}",interface.name.bold().green(),desc);
        }
        else {
            println!("{}", interface.name.bold().green());
        }
    }
    Ok(())
}

fn create_filter(cli: &Cli) -> Result<Option<String>> {
    let mut filter = String::new();

    if let Some(ports) = &cli.ports {
        if ports == "-" {
            // Все порты - не добавляем фильтр
            return Ok(None);
        }

        if ports.contains('-') {
            // Диапазон портов
            let parts: Vec<&str> = ports.split('-').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Неверный формат диапазона портов"));
            }
            let start: u16 = parts[0].parse()?;
            let end: u16 = parts[1].parse()?;
            filter.push_str(&format!("(portrange {}-{})", start, end));
        } else if ports.contains(',') {
            // Список портов
            let ports_list: Vec<&str> = ports.split(',').collect();
            filter.push_str(&format!("(port {} or port {})", ports_list[0], ports_list[1..].join(" or port ")));
        } else {
            // Одиночный порт
            let port: u16 = ports.parse()?;
            filter.push_str(&format!("port {}", port));
        }
    }

    if filter.is_empty() {
        Ok(None)
    } else {
        Ok(Some(filter))
    }
}
