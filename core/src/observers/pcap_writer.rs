use crate::capture::Observer;
use pcap::{Packet, Capture, Device};
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;
use log::error;
use std::fs::File;
use std::io::Write;

pub struct PcapWriter {
    file: Arc<Mutex<File>>,
    link_type: i32,
}

impl PcapWriter {
    pub fn new(filename: &str) -> Result<Self> {
        let device = Device::lookup()?;
        
        // Create a capture to get link type
        let capture = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        let link_type = capture.get_datalink().0;

        // Create and write PCAP header
        let file = File::create(filename)?;
        let writer = Self {
            file: Arc::new(Mutex::new(file)),
            link_type,
        };

        // Write PCAP file header
        writer.write_pcap_header()?;

        Ok(writer)
    }

    fn write_pcap_header(&self) -> Result<()> {
        let mut file = self.file.try_lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock file"))?;
        
        // Magic number (nanosecond resolution, little-endian)
        file.write_all(&[0xD4, 0xC3, 0xB2, 0xA1])?;
        
        // Version major (little-endian)
        file.write_all(&[0x02, 0x00])?;
        
        // Version minor (little-endian)
        file.write_all(&[0x04, 0x00])?;
        
        // Timezone offset (little-endian)
        file.write_all(&[0x00, 0x00, 0x00, 0x00])?;
        
        // Timestamp accuracy (little-endian)
        file.write_all(&[0x00, 0x00, 0x00, 0x00])?;
        
        // Snaplen (little-endian)
        file.write_all(&[0x00, 0x00, 0x04, 0x00])?;
        
        // Link type (little-endian)
        file.write_all(&self.link_type.to_le_bytes())?;

        Ok(())
    }

    fn write_packet(&self, packet: &Packet) -> Result<()> {
        let mut file = self.file.try_lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock file"))?;
        
        // Write packet header
        let ts_sec = packet.header.ts.tv_sec as u32;
        let ts_usec = packet.header.ts.tv_usec as u32;
        let len = packet.data.len() as u32;
        
        // Timestamp seconds (little-endian)
        file.write_all(&ts_sec.to_le_bytes())?;
        
        // Timestamp microseconds (little-endian)
        file.write_all(&ts_usec.to_le_bytes())?;
        
        // Captured length (little-endian)
        file.write_all(&len.to_le_bytes())?;
        
        // Original length (little-endian)
        file.write_all(&len.to_le_bytes())?;
        
        // Packet data
        file.write_all(packet.data)?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl Observer for PcapWriter {
    async fn update<'a>(&self, packet: &'a Packet<'a>) {
        if let Err(e) = self.write_packet(packet) {
            error!("Failed to write packet to PCAP file: {}", e);
        }
    }
} 