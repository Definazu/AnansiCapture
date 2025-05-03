use pnet::packet::icmp::IcmpPacket;

pub struct IcmpProcessor;

impl IcmpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<IcmpPacket<'a>> {
        IcmpPacket::new(data)
    }
} 