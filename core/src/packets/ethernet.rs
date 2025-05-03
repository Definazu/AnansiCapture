use pnet::packet::ethernet::EthernetPacket;

pub struct EthernetProcessor;

impl EthernetProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<EthernetPacket<'a>> {
        EthernetPacket::new(data)
    }
} 