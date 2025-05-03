use pnet::packet::udp::UdpPacket;

pub struct UdpProcessor;

impl UdpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<UdpPacket<'a>> {
        UdpPacket::new(data)
    }
} 