use pcap::{Capture, Device, Packet};
use crate::errors::CaptureError;
use tokio::sync::{Mutex, mpsc, RwLock};
use std::sync::Arc;
use log::{info, error};
use std::collections::HashMap;
use uuid::Uuid;

/// Интерфейс наблюдателя (Observer)
pub trait Observer: Send + Sync {
    fn update(&self, packet: &Packet);
}

/// Модуль захвата пакетов
pub struct PacketCapture {
    capture: Option<Arc<Mutex<Capture<pcap::Active>>>>,
    observers: Arc<RwLock<HashMap<Uuid, Arc<dyn Observer>>>>,
    is_running: Arc<Mutex<bool>>,
}

impl PacketCapture {
    /// Создает новый экземпляр PacketCapture
    pub fn new() -> Self {
        Self {
            capture: None,
            observers: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    /// Добавляет наблюдателя и возвращает его ID
    pub async fn add_observer(&mut self, observer: Arc<dyn Observer>) -> Uuid {
        let id = Uuid::new_v4();
        let mut observers = self.observers.write().await;
        observers.insert(id, observer);
        info!("Добавлен новый наблюдатель с ID: {}", id);
        id
    }

    /// Удаляет наблюдателя по ID
    pub async fn remove_observer(&mut self, id: Uuid) -> bool {
        let mut observers = self.observers.write().await;
        observers.remove(&id).is_some()
    }

    /// Запускает захват пакетов
    pub async fn start(&mut self, promiscuous: bool, filter: Option<&str>) -> Result<(), CaptureError> {
        let device = Device::lookup().map_err(|e| CaptureError::InterfaceOpenError(e.to_string()))?;
        let mut cap = Capture::from_device(device)
            .map_err(|e| CaptureError::InterfaceOpenError(e.to_string()))?
            .promisc(promiscuous)
            .open()
            .map_err(|e| CaptureError::CaptureFailure(e.to_string()))?;

        if let Some(f) = filter {
            cap.filter(f).map_err(|e| CaptureError::InvalidFilter(e.to_string()))?;
            info!("Применен фильтр: {}", f);
        }

        self.capture = Some(Arc::new(Mutex::new(cap)));
        *self.is_running.lock().await = true;

        let cap_mutex = Arc::clone(self.capture.as_ref().unwrap());
        let observers = Arc::clone(&self.observers);
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            let mut cap = cap_mutex.lock().await;
            while *is_running.lock().await {
                match cap.next() {
                    Ok(packet) => {
                        let observers = observers.read().await;
                        for observer in observers.values() {
                            observer.update(&packet);
                        }
                    }
                    Err(e) => {
                        error!("Ошибка при захвате пакета: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Останавливает захват пакетов
    pub async fn stop(&mut self) {
        *self.is_running.lock().await = false;
        self.capture = None;
        info!("Захват пакетов остановлен");
    }
}
