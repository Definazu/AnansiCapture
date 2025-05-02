use crate::capture::PacketCapture;
use crate::capture::Observer;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{info};
use uuid::Uuid;

pub struct AnansiFacade {
    capture: Arc<Mutex<PacketCapture>>,
}

impl AnansiFacade {
    /// Создает новый экземпляр фасада
    pub fn new() -> Self {
        Self {
            capture: Arc::new(Mutex::new(PacketCapture::new())),
        }
    }

    /// Запускает захват пакетов
    pub async fn start_capture(&self, promiscuous: bool, filter: Option<&str>) -> Result<(), crate::errors::CaptureError> {
        let mut capture = self.capture.lock().await;
        capture.start(promiscuous, filter).await
    }

    /// Останавливает захват пакетов
    pub async fn stop_capture(&self) {
        let mut capture = self.capture.lock().await;
        capture.stop().await;
    }

    /// Добавляет наблюдателя и возвращает его ID
    pub async fn add_observer(&self, observer: Arc<dyn Observer>) -> Uuid {
        let mut capture = self.capture.lock().await;
        capture.add_observer(observer).await
    }

    /// Удаляет наблюдателя по ID
    pub async fn remove_observer(&self, id: Uuid) -> bool {
        let mut capture = self.capture.lock().await;
        capture.remove_observer(id).await
    }
}
