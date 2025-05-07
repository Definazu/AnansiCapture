use anyhow::Result;

pub struct TlsProcessor;

impl TlsProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, payload: &[u8]) -> Result<TlsPacket> {
        if payload.len() < 5 {
            return Err(anyhow::anyhow!("Packet too short for TLS"));
        }

        let content_type = payload[0];
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

        if payload.len() < 5 + length {
            return Err(anyhow::anyhow!("Packet truncated"));
        }

        let tls_version = match version {
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => "Unknown TLS version",
        };

        let content_type_str = match content_type {
            0x14 => "Change Cipher Spec",
            0x15 => "Alert",
            0x16 => "Handshake",
            0x17 => "Application Data",
            0x18 => "Heartbeat",
            _ => "Unknown",
        };

        // Check for SSL/TLS handshake
        let handshake_type = if content_type == 0x16 && payload.len() > 5 {
            match payload[5] {
                0x01 => "Client Hello",
                0x02 => "Server Hello",
                0x0b => "Certificate",
                0x0c => "Server Key Exchange",
                0x0e => "Server Hello Done",
                0x10 => "Client Key Exchange",
                0x14 => "Finished",
                _ => "Unknown handshake type",
            }
        } else {
            "Continuation Data"
        };

        Ok(TlsPacket {
            version: tls_version.to_string(),
            content_type: content_type_str.to_string(),
            handshake_type: handshake_type.to_string(),
            length,
        })
    }
}

pub struct TlsPacket {
    version: String,
    content_type: String,
    handshake_type: String,
    length: usize,
}

impl TlsPacket {
    pub fn get_version(&self) -> &str {
        &self.version
    }

    pub fn get_content_type(&self) -> &str {
        &self.content_type
    }

    pub fn get_handshake_type(&self) -> &str {
        &self.handshake_type
    }

    pub fn get_length(&self) -> usize {
        self.length
    }

    pub fn format_info(&self) -> String {
        if self.content_type == "Handshake" {
            format!("{} {}", self.version, self.handshake_type)
        } else {
            format!("{} {}", self.version, self.content_type)
        }
    }
} 