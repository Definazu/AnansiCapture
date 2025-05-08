mod tcp;
mod udp;
mod icmp;
mod icmpv6;
mod ipv4;
mod ipv6;
mod ethernet;
mod arp;
mod dns;
mod dhcp;
mod http;
mod tls;
mod igmp;
mod smb;
mod ftp;

pub use tcp::TcpProcessor;
pub use udp::UdpProcessor;
pub use icmp::IcmpProcessor;
pub use icmpv6::Icmpv6Processor;
pub use ipv4::Ipv4Processor;
pub use ipv6::Ipv6Processor;
pub use ethernet::EthernetProcessor;
pub use arp::ArpProcessor;
pub use dns::DnsProcessor;
pub use dhcp::DhcpProcessor;
pub use http::HttpProcessor;
pub use tls::TlsProcessor;
pub use igmp::IgmpProcessor;
pub use smb::SmbProcessor;
pub use ftp::FtpProcessor;

use chrono::Local;
use colored::*;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;

pub struct PacketInfo {
    pub timestamp: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub protocol: String,
    pub length: usize,
    pub details: String,
}

pub struct PacketProcessor {
    debug_mode: bool,
    tcp_processor: TcpProcessor,
    udp_processor: UdpProcessor,
    icmp_processor: IcmpProcessor,
    icmpv6_processor: icmpv6::Icmpv6Processor,
    ipv4_processor: ipv4::Ipv4Processor,
    ipv6_processor: ipv6::Ipv6Processor,
    ethernet_processor: ethernet::EthernetProcessor,
    arp_processor: ArpProcessor,
    dns_processor: DnsProcessor,
    dhcp_processor: DhcpProcessor,
    http_processor: HttpProcessor,
    tls_processor: TlsProcessor,
    igmp_processor: IgmpProcessor,
    smb_processor: SmbProcessor,
    ftp_processor: FtpProcessor,
}

impl PacketProcessor {
    pub fn new(debug_mode: bool) -> Self {
        Self {
            debug_mode,
            tcp_processor: TcpProcessor::new(),
            udp_processor: UdpProcessor::new(),
            icmp_processor: IcmpProcessor::new(),
            icmpv6_processor: icmpv6::Icmpv6Processor::new(),
            ipv4_processor: ipv4::Ipv4Processor::new(),
            ipv6_processor: ipv6::Ipv6Processor::new(),
            ethernet_processor: ethernet::EthernetProcessor::new(),
            arp_processor: ArpProcessor::new(),
            dns_processor: DnsProcessor::new(),
            dhcp_processor: DhcpProcessor::new(),
            http_processor: HttpProcessor::new(),
            tls_processor: TlsProcessor::new(),
            igmp_processor: IgmpProcessor::new(),
            smb_processor: SmbProcessor::new(),
            ftp_processor: FtpProcessor::new(),
        }
    }

    pub fn process_packet(&self, packet: &pcap::Packet) -> PacketInfo {
        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
        let ethernet = self.ethernet_processor.process(packet.data).unwrap();
        
        let (source_ip, destination_ip, protocol, details) = match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4 = self.ipv4_processor.process(ethernet.payload()).unwrap();
                let source = ipv4.get_source();
                let destination = ipv4.get_destination();
                
                let (protocol, details) = match ipv4.get_next_level_protocol() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        let tcp = self.tcp_processor.process(ipv4.payload()).unwrap();
                        let payload = tcp.payload();
                        
                        // Check for TLS/SSL traffic (ports 443, 465, 993, 995)
                        if tcp.get_destination() == 443 || tcp.get_source() == 443 ||
                           tcp.get_destination() == 465 || tcp.get_source() == 465 ||
                           tcp.get_destination() == 993 || tcp.get_source() == 993 ||
                           tcp.get_destination() == 995 || tcp.get_source() == 995 {
                            if let Ok(tls) = self.tls_processor.process(payload) {
                                (
                                    "TLS".to_string(),
                                    format!("{} - {}", tls.get_version(), tls.format_info())
                                )
                            } else {
                                (
                                    "TCP".to_string(),
                                    TcpProcessor::format_tcp_info(&tcp)
                                )
                            }
                        } else if tcp.get_destination() == 445 || tcp.get_source() == 445 {
                            // Check for SMB traffic (port 445)
                            if let Ok(smb) = self.smb_processor.process(payload) {
                                (
                                    "SMB".to_string(),
                                    format!(
                                        "SMB Packet - Command: {}",
                                        self.smb_processor.get_command(&smb)
                                    )
                                )
                            } else {
                                (
                                    "TCP".to_string(),
                                    TcpProcessor::format_tcp_info(&tcp)
                                )
                            }
                        } else if tcp.get_destination() == 80 || tcp.get_source() == 80 {
                            // Check for HTTP traffic
                            if let Ok(http) = self.http_processor.process(payload) {
                                (
                                    "HTTP".to_string(),
                                    format!(
                                        "{} {} {}",
                                        http.get_method(),
                                        http.get_path(),
                                        http.get_host()
                                    )
                                )
                            } else {
                                (
                                    "TCP".to_string(),
                                    TcpProcessor::format_tcp_info(&tcp)
                                )
                            }
                        } else {
                            (
                                "TCP".to_string(),
                                TcpProcessor::format_tcp_info(&tcp)
                            )
                        }
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                        let udp = self.udp_processor.process(ipv4.payload()).unwrap();
                        let payload = udp.payload();
                        
                        // Check for DNS traffic
                        if udp.get_destination() == 53 || udp.get_source() == 53 {
                            if let Ok(dns) = self.dns_processor.process(payload) {
                                (
                                    "DNS".to_string(),
                                    self.dns_processor.get_query_info(&dns)
                                )
                            } else {
                                (
                                    "UDP".to_string(),
                                    format!(
                                        "{}:{} > {}:{} UDP, length {}",
                                        source,
                                        udp.get_source(),
                                        destination,
                                        udp.get_destination(),
                                        ipv4.payload().len()
                                    )
                                )
                            }
                        } else {
                            (
                                "UDP".to_string(),
                                format!(
                                    "{}:{} > {}:{} UDP, length {}",
                                    source,
                                    udp.get_source(),
                                    destination,
                                    udp.get_destination(),
                                    ipv4.payload().len()
                                )
                            )
                        }
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                        let icmp = self.icmp_processor.process(ipv4.payload()).unwrap();
                        (
                            "ICMP".to_string(),
                            format!(
                                "{} > {}: {}",
                                source,
                                destination,
                                self.icmp_processor.get_icmp_type(&icmp)
                            )
                        )
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Igmp => {
                        if let Ok(igmp) = self.igmp_processor.process(ipv4.payload()) {
                            (
                                "IGMP".to_string(),
                                igmp.format_info()
                            )
                        } else {
                            (
                                "IGMP".to_string(),
                                format!("Unknown IGMP packet, length {}", ipv4.payload().len())
                            )
                        }
                    }
                    _ => (
                        format!("Unknown({})", ipv4.get_next_level_protocol()),
                        format!("Unknown protocol, length {}", ipv4.payload().len())
                    )
                };
                
                (source.to_string(), destination.to_string(), protocol, details)
            }
            EtherTypes::Ipv6 => {
                let ipv6 = self.ipv6_processor.process(ethernet.payload()).unwrap();
                let source = ipv6.get_source();
                let destination = ipv6.get_destination();
                
                let (protocol, details) = match ipv6.get_next_header() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        let tcp = self.tcp_processor.process(ipv6.payload()).unwrap();
                        (
                            "TCP".to_string(),
                            format!(
                                "Flags [{}], seq {}, ack {}, win {}, length {}",
                                tcp.get_flags(),
                                tcp.get_sequence(),
                                tcp.get_acknowledgement(),
                                tcp.get_window(),
                                ipv6.payload().len()
                            )
                        )
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                        let _udp = self.udp_processor.process(ipv6.payload()).unwrap();
                        (
                            "UDP".to_string(),
                            format!(
                                "UDP, length {}",
                                ipv6.payload().len()
                            )
                        )
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                        let _icmpv6 = self.icmpv6_processor.process(ipv6.payload()).unwrap();
                        (
                            "ICMPv6".to_string(),
                            format!(
                                "{} > {}: ICMPv6, length {}",
                                source,
                                destination,
                                ipv6.payload().len()
                            )
                        )
                    }
                    _ => (
                        format!("Unknown({})", ipv6.get_next_header()),
                        format!("{} > {}: Unknown protocol", source, destination)
                    )
                };
                
                (source.to_string(), destination.to_string(), protocol, details)
            }
            EtherTypes::Arp => {
                let arp = self.arp_processor.process(ethernet.payload()).unwrap();
                let source = format_mac(&ethernet.get_source().octets());
                let destination = format_mac(&ethernet.get_destination().octets());
                (
                    source,
                    destination,
                    "ARP".to_string(),
                    ArpProcessor::format_arp_info(&arp)
                )
            }
            _ => (
                "Unknown".to_string(),
                "Unknown".to_string(),
                "Unknown".to_string(),
                format!("Unknown ethertype: {}", ethernet.get_ethertype())
            )
        };

        PacketInfo {
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            length: packet.data.len(),
            details,
        }
    }

    pub fn format_packet_info(&self, info: &PacketInfo) -> String {
        let protocol_color = match info.protocol.as_str() {
            "TCP" => "yellow",
            "UDP" => "green",
            "ICMP" => "blue",
            "ICMPv6" => "cyan",
            "ARP" => "magenta",
            "DNS" => "bright_blue",
            "DHCP" => "bright_green",
            "HTTP" => "bright_yellow",
            "TLS" => "bright_magenta",
            "IGMP" => "bright_cyan",
            "SMB" => "bright_purple",
            "FTP" => "bright_red",
            _ => "white",
        };

        format!(
            "{} {} -> {} {} {} {}",
            info.timestamp.cyan(),
            info.source_ip,
            info.destination_ip,
            info.protocol.color(protocol_color),
            info.length,
            info.details
        )
    }
}

fn format_mac(mac: &[u8]) -> String {
    if mac.iter().all(|&b| b == 0) {
        return "Broadcast".to_string();
    }
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":")
}
