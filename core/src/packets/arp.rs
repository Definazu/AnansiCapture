use pnet::packet::arp::ArpPacket;
use std::net::Ipv4Addr;

pub struct ArpProcessor;

impl ArpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<ArpPacket<'a>> {
        ArpPacket::new(data)
    }

    pub fn format_arp_info(packet: &ArpPacket) -> String {
        let operation = packet.get_operation();
        let sender_ip = Ipv4Addr::from(packet.get_sender_proto_addr());
        let target_ip = Ipv4Addr::from(packet.get_target_proto_addr());
        let sender_mac = format_mac(&packet.get_sender_hw_addr().octets());
        let _target_mac = format_mac(&packet.get_target_hw_addr().octets());

        match operation.0 {
            1 => format!("Who has {}? Tell {}", target_ip, sender_ip),
            2 => format!("{} is at {}", sender_ip, sender_mac),
            _ => format!("Unknown ARP operation: {}", operation.0)
        }
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