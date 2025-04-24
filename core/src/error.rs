use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("PCAP error: {0}")]
    PcapError(#[from] pcap::Error),
    
    #[error("Capture already running")]
    CaptureAlreadyRunning,
    
    #[error("Interface not found")]
    InterfaceNotFound,
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}