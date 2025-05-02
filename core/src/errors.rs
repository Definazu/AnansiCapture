use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("Ошибка при открытии сетевого интерфейса: {0}")]
    InterfaceOpenError(String),

    #[error("Ошибка при захвате пакетов: {0}")]
    CaptureFailure(String),

    #[error("Неверный фильтр: {0}")]
    InvalidFilter(String),

    #[error("Неизвестная ошибка")]
    Unknown,
}
