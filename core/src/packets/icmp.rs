use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::Packet;

pub struct IcmpProcessor;

impl IcmpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<IcmpPacket<'a>> {
        IcmpPacket::new(data)
    }

    pub fn get_icmp_type(&self, packet: &IcmpPacket) -> String {
        match packet.get_icmp_type() {
            IcmpTypes::EchoRequest => {
                if let Some(echo) = EchoRequestPacket::new(packet.payload()) {
                    format!("Echo Request (id={}, seq={})", echo.get_identifier(), echo.get_sequence_number())
                } else {
                    "Echo Request".to_string()
                }
            }
            IcmpTypes::EchoReply => {
                if let Some(echo) = EchoReplyPacket::new(packet.payload()) {
                    format!("Echo Reply (id={}, seq={})", echo.get_identifier(), echo.get_sequence_number())
                } else {
                    "Echo Reply".to_string()
                }
            }
            IcmpTypes::DestinationUnreachable => "Destination Unreachable".to_string(),
            IcmpTypes::TimeExceeded => "Time Exceeded".to_string(),
            IcmpTypes::ParameterProblem => "Parameter Problem".to_string(),
            IcmpTypes::SourceQuench => "Source Quench".to_string(),
            IcmpTypes::TimestampReply => "Timestamp Reply".to_string(),
            IcmpTypes::AddressMaskRequest => "Address Mask Request".to_string(),
            IcmpTypes::AddressMaskReply => "Address Mask Reply".to_string(),
            _ => format!("Unknown ICMP type: {}", packet.get_icmp_type().0),
        }
    }
} 