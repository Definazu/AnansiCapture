use pnet::packet::ipv6::Ipv6Packet;

pub struct Ipv6Processor;

impl Ipv6Processor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<Ipv6Packet<'a>> {
        Ipv6Packet::new(data)
    }
} 