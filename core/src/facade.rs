use crate::capture::{PacketCapture, Observer};
use crate::interface::{list_interfaces, get_interface_names, validate_interface};
use crate::packets::{PacketProcessor, PacketInfo};
use crate::observers::PcapWriter;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct AnansiFacade {
    capture: Arc<Mutex<Option<PacketCapture>>>,
    observers: Arc<Mutex<Vec<(Uuid, Arc<dyn Observer + Send + Sync>)>>>,
    packet_processor: PacketProcessor,
    pcap_writer: Option<Arc<PcapWriter>>,
}

impl AnansiFacade {
    /// Создает новый экземпляр фасада
    pub fn new(debug_mode: bool) -> Self {
        Self {
            capture: Arc::new(Mutex::new(None)),
            observers: Arc::new(Mutex::new(Vec::new())),
            packet_processor: PacketProcessor::new(debug_mode),
            pcap_writer: None,
        }
    }

    /// Устанавливает файл для сохранения PCAP
    pub async fn set_pcap_output(&mut self, filename: &str) -> Result<()> {
        let writer = PcapWriter::new(filename)?;
        self.pcap_writer = Some(Arc::new(writer));
        Ok(())
    }

    /// Запускает захват пакетов
    pub async fn start_capture(&self, interface: &str, filter: Option<&str>) -> Result<()> {
        let mut capture = self.capture.lock().await;
        if capture.is_some() {
            return Err(anyhow::anyhow!("Capture is already running"));
        }

        let mut new_capture = PacketCapture::new();
        new_capture.set_interface(interface)?;
        
        if let Some(filter) = filter {
            new_capture.set_filter(filter)?;
        }

        let observers = self.observers.lock().await;
        for (_, observer) in observers.iter() {
            new_capture.add_observer(observer.clone()).await;
        }

        // Add PCAP writer if configured
        if let Some(writer) = &self.pcap_writer {
            new_capture.add_observer(writer.clone()).await;
        }

        new_capture.start().await?;
        *capture = Some(new_capture);
        Ok(())
    }

    /// Останавливает захват пакетов
    pub async fn stop_capture(&self) {
        let mut capture = self.capture.lock().await;
        if let Some(mut capture) = capture.take() {
            capture.stop().await;
        }
    }

    /// Добавляет наблюдателя и возвращает его ID
    pub async fn add_observer(&self, observer: Arc<dyn Observer + Send + Sync>) -> Uuid {
        let id = Uuid::new_v4();
        let mut observers = self.observers.lock().await;
        observers.push((id, observer));
        id
    }

    /// Удаляет наблюдателя по ID
    pub async fn remove_observer(&self, id: Uuid) {
        let mut observers = self.observers.lock().await;
        observers.retain(|(observer_id, _)| *observer_id != id);
    }

    pub async fn list_interfaces(&self) -> Result<Vec<String>> {
        get_interface_names()
    }

    pub async fn validate_interface(&self, interface_name: &str) -> Result<bool> {
        validate_interface(interface_name)
    }

    pub fn process_packet(&self, packet: &pcap::Packet) -> PacketInfo {
        self.packet_processor.process_packet(packet)
    }

    pub fn format_packet_info(&self, info: &PacketInfo) -> String {
        self.packet_processor.format_packet_info(info)
    }
}
