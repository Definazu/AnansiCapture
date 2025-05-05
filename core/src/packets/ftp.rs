use anyhow::Result;
use std::str;

pub struct FtpProcessor;

impl FtpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, payload: &[u8]) -> Result<FtpPacket> {
        // Try to parse the payload as UTF-8 string
        if let Ok(text) = str::from_utf8(payload) {
            // Check if it's a command (starts with a command code)
            if let Some((code, message)) = text.split_once(' ') {
                if code.chars().all(|c| c.is_ascii_digit()) {
                    return Ok(FtpPacket::Response {
                        code: code.to_string(),
                        message: message.trim().to_string(),
                    });
                }
            }
            
            // If it's not a response, treat it as a command
            return Ok(FtpPacket::Command(text.trim().to_string()));
        }

        Err(anyhow::anyhow!("Failed to parse FTP packet"))
    }
}

pub enum FtpPacket {
    Command(String),
    Response {
        code: String,
        message: String,
    },
}

impl FtpPacket {
    pub fn get_command(&self) -> String {
        match self {
            FtpPacket::Command(cmd) => cmd.to_string(),
            FtpPacket::Response { code, message } => format!("{} {}", code, message),
        }
    }

    pub fn is_command(&self) -> bool {
        matches!(self, FtpPacket::Command(_))
    }

    pub fn is_response(&self) -> bool {
        matches!(self, FtpPacket::Response { .. })
    }
} 