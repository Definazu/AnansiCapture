use std::net::Ipv4Addr;
use anyhow::Result;

#[derive(Debug)]
pub struct IgmpPacket {
    type_: u8,
    max_resp_time: u8,
    checksum: u16,
    group_address: Ipv4Addr,
}

impl IgmpPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self> {
        if payload.len() < 8 {
            return Err(anyhow::anyhow!("IGMP packet too short"));
        }

        Ok(Self {
            type_: payload[0],
            max_resp_time: payload[1],
            checksum: u16::from_be_bytes([payload[2], payload[3]]),
            group_address: Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]),
        })
    }

    pub fn get_type(&self) -> IgmpType {
        match self.type_ {
            0x11 => IgmpType::MembershipQuery,
            0x12 => IgmpType::MembershipReportV1,
            0x16 => IgmpType::MembershipReportV2,
            0x17 => IgmpType::LeaveGroup,
            0x22 => IgmpType::MembershipReportV3,
            _ => IgmpType::Unknown,
        }
    }

    pub fn get_group_address(&self) -> String {
        self.group_address.to_string()
    }
}

#[derive(Debug)]
pub enum IgmpType {
    MembershipQuery,
    MembershipReportV1,
    MembershipReportV2,
    LeaveGroup,
    MembershipReportV3,
    Unknown,
}

pub struct IgmpProcessor;

impl IgmpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, payload: &[u8]) -> Result<IgmpPacket> {
        IgmpPacket::from_bytes(payload)
    }
} 