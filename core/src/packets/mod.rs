mod tcp;
mod udp;
mod icmp;
mod icmpv6;
mod ipv4;
mod ipv6;
mod ethernet;
mod arp;

pub use tcp::TcpProcessor;
pub use udp::UdpProcessor;
pub use icmp::IcmpProcessor;
pub use icmpv6::Icmpv6Processor;
pub use ipv4::Ipv4Processor;
pub use ipv6::Ipv6Processor;
pub use ethernet::EthernetProcessor;
pub use arp::ArpProcessor;

use chrono::Local;
use colored::*;
use pnet::packet::Packet;

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
    tcp: TcpProcessor,
    udp: UdpProcessor,
    icmp: IcmpProcessor,
    icmpv6: Icmpv6Processor,
    ipv4: Ipv4Processor,
    ipv6: Ipv6Processor,
    ethernet: EthernetProcessor,
    arp: ArpProcessor,
}

impl PacketProcessor {
    pub fn new(debug_mode: bool) -> Self {
        Self {
            debug_mode,
            tcp: TcpProcessor::new(),
            udp: UdpProcessor::new(),
            icmp: IcmpProcessor::new(),
            icmpv6: Icmpv6Processor::new(),
            ipv4: Ipv4Processor::new(),
            ipv6: Ipv6Processor::new(),
            ethernet: EthernetProcessor::new(),
            arp: ArpProcessor::new(),
        }
    }

    pub fn process_packet(&self, packet: &pcap::Packet) -> PacketInfo {
        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
        let ethernet = self.ethernet.process(packet.data).unwrap();
        
        let (source_ip, destination_ip, protocol, details) = match ethernet.get_ethertype() {
            pnet::packet::ethernet::EtherTypes::Ipv4 => {
                let ipv4 = self.ipv4.process(ethernet.payload()).unwrap();
                let source = ipv4.get_source();
                let destination = ipv4.get_destination();
                
                let (protocol, details) = match ipv4.get_next_level_protocol() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        let tcp = self.tcp.process(ipv4.payload()).unwrap();
                        (
                            "TCP".to_string(),
                            format!(
                                "{}:{} > {}:{} Flags [{}], seq {}, ack {}, win {}, length {}",
                                source,
                                tcp.get_source(),
                                destination,
                                tcp.get_destination(),
                                tcp.get_flags(),
                                tcp.get_sequence(),
                                tcp.get_acknowledgement(),
                                tcp.get_window(),
                                ipv4.payload().len()
                            )
                        )
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                        let udp = self.udp.process(ipv4.payload()).unwrap();
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
                    pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                        let _icmp = self.icmp.process(ipv4.payload()).unwrap();
                        (
                            "ICMP".to_string(),
                            format!(
                                "ICMP, length {}",
                                ipv4.payload().len()
                            )
                        )
                    }
                    _ => (
                        format!("Unknown({})", ipv4.get_next_level_protocol()),
                        format!("Unknown protocol, length {}", ipv4.payload().len())
                    )
                };
                
                (source.to_string(), destination.to_string(), protocol, details)
            }
            pnet::packet::ethernet::EtherTypes::Ipv6 => {
                let ipv6 = self.ipv6.process(ethernet.payload()).unwrap();
                let source = ipv6.get_source();
                let destination = ipv6.get_destination();
                
                let (protocol, details) = match ipv6.get_next_header() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        let tcp = self.tcp.process(ipv6.payload()).unwrap();
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
                        let _udp = self.udp.process(ipv6.payload()).unwrap();
                        (
                            "UDP".to_string(),
                            format!(
                                "UDP, length {}",
                                ipv6.payload().len()
                            )
                        )
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Icmpv6 => {
                        let _icmpv6 = self.icmpv6.process(ipv6.payload()).unwrap();
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
            pnet::packet::ethernet::EtherTypes::Arp => {
                let arp = self.arp.process(ethernet.payload()).unwrap();
                let source = arp.get_sender_proto_addr().to_string();
                let destination = arp.get_target_proto_addr().to_string();
                (
                    source,
                    destination,
                    "ARP".to_string(),
                    format!(
                        "ARP, {} -> {}, length {}",
                        arp.get_sender_proto_addr(),
                        arp.get_target_proto_addr(),
                        ethernet.payload().len()
                    )
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
            _ => "white",
        };

        if self.debug_mode {
            format!(
                "{} {} {}",
                info.timestamp.cyan(),
                info.protocol.color(protocol_color),
                info.details
            )
        } else {
            format!(
                "{} {} {}",
                info.timestamp.cyan(),
                info.protocol.color(protocol_color),
                info.details
            )
        }
    }
} 