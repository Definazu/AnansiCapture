use pnet::packet::ipv4::Ipv4Packet;

pub struct Ipv4Processor;

impl Ipv4Processor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<Ipv4Packet<'a>> {
        Ipv4Packet::new(data)
    }
} 