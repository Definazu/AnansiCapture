use pnet::packet::icmpv6::Icmpv6Packet;

pub struct Icmpv6Processor;

impl Icmpv6Processor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<Icmpv6Packet<'a>> {
        Icmpv6Packet::new(data)
    }
} 