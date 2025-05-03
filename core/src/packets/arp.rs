use pnet::packet::arp::ArpPacket;

pub struct ArpProcessor;

impl ArpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<ArpPacket<'a>> {
        ArpPacket::new(data)
    }
} 