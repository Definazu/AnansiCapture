use anyhow::Result;

pub struct TlsProcessor;

impl TlsProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, payload: &[u8]) -> Result<TlsPacket> {
        // Проверяем, что это TLS handshake
        if payload.len() < 5 || payload[0] != 0x16 {
            return Err(anyhow::anyhow!("Not a TLS handshake"));
        }

        // Проверяем версию TLS
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        let tls_version = match version {
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => "Unknown TLS version",
        };

        // Проверяем тип handshake
        let handshake_type = payload[5];
        let handshake_name = match handshake_type {
            0x01 => "Client Hello",
            0x02 => "Server Hello",
            0x0b => "Certificate",
            0x0c => "Server Key Exchange",
            0x0e => "Server Hello Done",
            0x10 => "Client Key Exchange",
            0x14 => "Finished",
            _ => "Unknown handshake type",
        };

        Ok(TlsPacket {
            version: tls_version.to_string(),
            handshake_type: handshake_name.to_string(),
        })
    }
}

pub struct TlsPacket {
    version: String,
    handshake_type: String,
}

impl TlsPacket {
    pub fn get_version(&self) -> &str {
        &self.version
    }

    pub fn get_handshake_type(&self) -> &str {
        &self.handshake_type
    }
} 