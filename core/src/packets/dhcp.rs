use std::net::Ipv4Addr;
use anyhow::Result;

#[derive(Debug)]
pub struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    options: Vec<DhcpOption>,
}

#[derive(Debug)]
pub struct DhcpOption {
    code: u8,
    length: u8,
    value: Vec<u8>,
}

impl DhcpPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self> {
        if payload.len() < 240 {
            return Err(anyhow::anyhow!("DHCP packet too short"));
        }

        let mut options = Vec::new();
        let mut i = 240; // Начало секции опций

        while i < payload.len() {
            if payload[i] == 0xff { // Конец опций
                break;
            }

            let code = payload[i];
            let length = payload[i + 1];
            let value = payload[i + 2..i + 2 + length as usize].to_vec();
            
            options.push(DhcpOption {
                code,
                length,
                value,
            });

            i += 2 + length as usize;
        }

        Ok(Self {
            op: payload[0],
            htype: payload[1],
            hlen: payload[2],
            hops: payload[3],
            xid: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
            secs: u16::from_be_bytes([payload[8], payload[9]]),
            flags: u16::from_be_bytes([payload[10], payload[11]]),
            ciaddr: Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]),
            yiaddr: Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]),
            siaddr: Ipv4Addr::new(payload[20], payload[21], payload[22], payload[23]),
            giaddr: Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]),
            chaddr: payload[28..44].try_into().unwrap(),
            sname: payload[44..108].try_into().unwrap(),
            file: payload[108..236].try_into().unwrap(),
            options,
        })
    }

    pub fn get_message_type(&self) -> String {
        for option in &self.options {
            if option.code == 53 { // DHCP Message Type
                return match option.value[0] {
                    1 => "DHCPDISCOVER".to_string(),
                    2 => "DHCPOFFER".to_string(),
                    3 => "DHCPREQUEST".to_string(),
                    4 => "DHCPDECLINE".to_string(),
                    5 => "DHCPACK".to_string(),
                    6 => "DHCPNAK".to_string(),
                    7 => "DHCPRELEASE".to_string(),
                    8 => "DHCPINFORM".to_string(),
                    _ => "Unknown".to_string(),
                };
            }
        }
        "Unknown".to_string()
    }

    pub fn get_client_ip(&self) -> String {
        self.yiaddr.to_string()
    }

    pub fn get_server_ip(&self) -> String {
        self.siaddr.to_string()
    }
}

pub struct DhcpProcessor;

impl DhcpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, payload: &[u8]) -> Result<DhcpPacket> {
        DhcpPacket::from_bytes(payload)
    }
} 