use async_trait::async_trait;
use pcap::{Capture, Device, Packet};
use tokio::sync::mpsc;
use std::sync::Arc;
use crate::error::CoreError;

pub struct CaptureOptions {
    pub promiscuous: bool,
    pub filter: Option<String>,
    pub buffer_size: i32,
}

pub struct AnansiCapture {
    active_capture: Option<tokio::task::JoinHandle<()>>,
    sender: Option<mpsc::Sender<Packet<'static>>>,
}

impl AnansiCapture {
    pub fn new() -> Self {
        Self {
            active_capture: None,
            sender: None,
        }
    }

    pub fn list_interfaces(&self) -> Result<Vec<Device>, CoreError> {
        let devices = Device::list()?;
        Ok(devices)
    }

    pub async fn start_capture(
        &mut self,
        interface: &str,
        options: CaptureOptions,
    ) -> Result<mpsc::Receiver<Packet<'static>>, CoreError> {
        if self.active_capture.is_some() {
            return Err(CoreError::CaptureAlreadyRunning);
        }

        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or(CoreError::InterfaceNotFound)?;

        let (sender, receiver) = mpsc::channel(100);
        self.sender = Some(sender);

        let mut cap = Capture::from_device(device)?
            .promisc(options.promiscuous)
            .buffer_size(options.buffer_size)
            .open()?;

        if let Some(filter) = options.filter {
            cap.filter(&filter)?;
        }

        let sender = self.sender.clone().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok(packet) = cap.next_packet() {
                let _ = sender.send(packet.to_owned()).await;
            }
        });

        self.active_capture = Some(handle);
        Ok(receiver)
    }

    pub fn stop_capture(&mut self) {
        if let Some(handle) = self.active_capture.take() {
            handle.abort();
        }
        self.sender.take();
    }

    pub fn save_to_pcap(&self, path: &str, packets: &[Packet]) -> Result<(), CoreError> {
        let mut savefile = Capture::dead(pcap::Linktype::ETHERNET)?
            .savefile(path)?;
            
        for packet in packets {
            savefile.write(packet);
        }
        Ok(())
    }

    pub fn load_from_pcap(&self, path: &str) -> Result<Vec<Packet<'static>>, CoreError> {
        let mut cap = Capture::from_file(path)?;
        let mut packets = Vec::new();
        
        while let Ok(packet) = cap.next_packet() {
            packets.push(packet.to_owned());
        }
        
        Ok(packets)
    }
}