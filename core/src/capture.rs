use pcap::{Capture, Device, Active, Inactive};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;
use anyhow::Result;
use log::{info, error};
use crate::errors::CaptureError;

#[async_trait::async_trait]
pub trait Observer: Send + Sync {
    async fn update<'a>(&self, packet: &'a pcap::Packet<'a>);
}

/// Модуль захвата пакетов
pub struct PacketCapture {
    capture: Arc<Mutex<Option<Capture<Active>>>>,
    observers: Arc<RwLock<Vec<(Uuid, Arc<dyn Observer>)>>>,
    interface: String,
    filter: Option<String>,
}

impl PacketCapture {
    /// Создает новый экземпляр PacketCapture
    pub fn new() -> Self {
        Self {
            capture: Arc::new(Mutex::new(None)),
            observers: Arc::new(RwLock::new(Vec::new())),
            interface: String::new(),
            filter: None,
        }
    }

    /// Устанавливает интерфейс захвата
    pub fn set_interface(&mut self, interface: &str) -> Result<()> {
        self.interface = interface.to_string();
        Ok(())
    }

    /// Устанавливает фильтр захвата
    pub fn set_filter(&mut self, filter: &str) -> Result<()> {
        self.filter = Some(filter.to_string());
        Ok(())
    }

    /// Добавляет наблюдателя и возвращает его ID
    pub async fn add_observer(&mut self, observer: Arc<dyn Observer>) -> Uuid {
        let id = Uuid::new_v4();
        let mut observers = self.observers.write().await;
        observers.push((id, observer));
        id
    }

    /// Удаляет наблюдателя по ID
    pub async fn remove_observer(&mut self, id: Uuid) -> bool {
        let mut observers = self.observers.write().await;
        let len_before = observers.len();
        observers.retain(|(observer_id, _)| *observer_id != id);
        observers.len() != len_before
    }

    /// Запускает захват пакетов
    pub async fn start(&mut self) -> Result<()> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == self.interface)
            .ok_or_else(|| CaptureError::InterfaceOpenError(format!("Interface {} not found", self.interface)))?;

        let mut capture: Capture<Inactive> = Capture::from_device(device)?;
        capture = capture.promisc(true);
        
        let mut capture: Capture<Active> = capture.open()?;
        
        if let Some(ref filter) = self.filter {
            capture.filter(filter)?;
        }

        let observers = self.observers.clone();
        
        *self.capture.lock().await = Some(capture);
        
        let capture = self.capture.clone();
        tokio::spawn(async move {
            loop {
                let mut capture = capture.lock().await;
                if let Some(capture) = capture.as_mut() {
                    match capture.next() {
                        Ok(packet) => {
                            let observers = observers.read().await;
                            for (_, observer) in observers.iter() {
                                observer.update(&packet).await;
                            }
                        }
                        Err(e) => {
                            error!("Error capturing packet: {}", e);
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
        });

        info!("Started capture on interface: {}", self.interface);
        Ok(())
    }

    /// Останавливает захват пакетов
    pub async fn stop(&mut self) {
        *self.capture.lock().await = None;
        info!("Stopped capture on interface: {}", self.interface);
    }
}

