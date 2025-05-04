#[derive(Debug)]
pub struct SmbPacket {
    pub command: u8,
    pub status: u32,
    pub flags: u8,
    pub flags2: u16,
    pub pid_high: u16,
    pub signature: [u8; 8],
    pub reserved: u16,
    pub tid: u16,
    pub pid_low: u16,
    pub uid: u16,
    pub mid: u16,
}

pub struct SmbProcessor;

impl SmbProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, payload: &[u8]) -> Result<SmbPacket, String> {
        if payload.len() < 32 {
            return Err("Packet too short for SMB header".to_string());
        }

        // Check for SMB signature (0xFF, 'S', 'M', 'B')
        if payload[0] != 0xFF || payload[1] != b'S' || payload[2] != b'M' || payload[3] != b'B' {
            return Err("Invalid SMB signature".to_string());
        }

        Ok(SmbPacket {
            command: payload[4],
            status: u32::from_le_bytes([payload[5], payload[6], payload[7], payload[8]]),
            flags: payload[9],
            flags2: u16::from_le_bytes([payload[10], payload[11]]),
            pid_high: u16::from_le_bytes([payload[12], payload[13]]),
            signature: [
                payload[14], payload[15], payload[16], payload[17],
                payload[18], payload[19], payload[20], payload[21],
            ],
            reserved: u16::from_le_bytes([payload[22], payload[23]]),
            tid: u16::from_le_bytes([payload[24], payload[25]]),
            pid_low: u16::from_le_bytes([payload[26], payload[27]]),
            uid: u16::from_le_bytes([payload[28], payload[29]]),
            mid: u16::from_le_bytes([payload[30], payload[31]]),
        })
    }

    pub fn get_command(&self, packet: &SmbPacket) -> String {
        match packet.command {
            0x00 => "SMB_COM_CREATE_DIRECTORY".to_string(),
            0x01 => "SMB_COM_DELETE_DIRECTORY".to_string(),
            0x02 => "SMB_COM_OPEN".to_string(),
            0x03 => "SMB_COM_CREATE".to_string(),
            0x04 => "SMB_COM_CLOSE".to_string(),
            0x05 => "SMB_COM_FLUSH".to_string(),
            0x06 => "SMB_COM_DELETE".to_string(),
            0x07 => "SMB_COM_RENAME".to_string(),
            0x08 => "SMB_COM_QUERY_INFORMATION".to_string(),
            0x09 => "SMB_COM_SET_INFORMATION".to_string(),
            0x0A => "SMB_COM_READ".to_string(),
            0x0B => "SMB_COM_WRITE".to_string(),
            0x0C => "SMB_COM_LOCK_BYTE_RANGE".to_string(),
            0x0D => "SMB_COM_UNLOCK_BYTE_RANGE".to_string(),
            0x0E => "SMB_COM_CREATE_TEMPORARY".to_string(),
            0x0F => "SMB_COM_CREATE_NEW".to_string(),
            0x10 => "SMB_COM_CHECK_DIRECTORY".to_string(),
            0x11 => "SMB_COM_PROCESS_EXIT".to_string(),
            0x12 => "SMB_COM_SEEK".to_string(),
            0x13 => "SMB_COM_LOCK_AND_READ".to_string(),
            0x14 => "SMB_COM_WRITE_AND_UNLOCK".to_string(),
            0x15 => "SMB_COM_READ_RAW".to_string(),
            0x16 => "SMB_COM_READ_MPX".to_string(),
            0x17 => "SMB_COM_READ_MPX_SECONDARY".to_string(),
            0x18 => "SMB_COM_WRITE_RAW".to_string(),
            0x19 => "SMB_COM_WRITE_MPX".to_string(),
            0x1A => "SMB_COM_WRITE_MPX_SECONDARY".to_string(),
            0x1B => "SMB_COM_WRITE_COMPLETE".to_string(),
            0x1C => "SMB_COM_QUERY_SERVER".to_string(),
            0x1D => "SMB_COM_SET_INFORMATION2".to_string(),
            0x1E => "SMB_COM_QUERY_INFORMATION2".to_string(),
            0x1F => "SMB_COM_LOCKING_ANDX".to_string(),
            0x20 => "SMB_COM_TRANSACTION".to_string(),
            0x21 => "SMB_COM_TRANSACTION_SECONDARY".to_string(),
            0x22 => "SMB_COM_IOCTL".to_string(),
            0x23 => "SMB_COM_IOCTL_SECONDARY".to_string(),
            0x24 => "SMB_COM_COPY".to_string(),
            0x25 => "SMB_COM_MOVE".to_string(),
            0x26 => "SMB_COM_ECHO".to_string(),
            0x27 => "SMB_COM_WRITE_AND_CLOSE".to_string(),
            0x28 => "SMB_COM_OPEN_ANDX".to_string(),
            0x29 => "SMB_COM_READ_ANDX".to_string(),
            0x2A => "SMB_COM_WRITE_ANDX".to_string(),
            0x2B => "SMB_COM_NEW_FILE_SIZE".to_string(),
            0x2C => "SMB_COM_CLOSE_AND_TREE_DISC".to_string(),
            0x2D => "SMB_COM_TRANSACTION2".to_string(),
            0x2E => "SMB_COM_TRANSACTION2_SECONDARY".to_string(),
            0x2F => "SMB_COM_FIND_CLOSE2".to_string(),
            0x30 => "SMB_COM_FIND_NOTIFY_CLOSE".to_string(),
            0x31 => "SMB_COM_QUERY_FS_INFORMATION".to_string(),
            0x32 => "SMB_COM_SET_FS_INFORMATION".to_string(),
            0x33 => "SMB_COM_FIND_NOTIFY".to_string(),
            0x34 => "SMB_COM_FIND_NOTIFY2".to_string(),
            0x35 => "SMB_COM_TREE_CONNECT".to_string(),
            0x36 => "SMB_COM_TREE_DISCONNECT".to_string(),
            0x37 => "SMB_COM_NEGOTIATE".to_string(),
            0x38 => "SMB_COM_SESSION_SETUP_ANDX".to_string(),
            0x39 => "SMB_COM_LOGOFF_ANDX".to_string(),
            0x3A => "SMB_COM_TREE_CONNECT_ANDX".to_string(),
            0x3B => "SMB_COM_QUERY_INFORMATION_DISK".to_string(),
            0x3C => "SMB_COM_SEARCH".to_string(),
            0x3D => "SMB_COM_FIND".to_string(),
            0x3E => "SMB_COM_FIND_UNIQUE".to_string(),
            0x3F => "SMB_COM_FIND_CLOSE".to_string(),
            0x40 => "SMB_COM_NT_TRANSACT".to_string(),
            0x41 => "SMB_COM_NT_TRANSACT_SECONDARY".to_string(),
            0x42 => "SMB_COM_NT_CREATE_ANDX".to_string(),
            0x43 => "SMB_COM_NT_CANCEL".to_string(),
            0x44 => "SMB_COM_NT_RENAME".to_string(),
            0x45 => "SMB_COM_OPEN_PRINT_FILE".to_string(),
            0x46 => "SMB_COM_WRITE_PRINT_FILE".to_string(),
            0x47 => "SMB_COM_CLOSE_PRINT_FILE".to_string(),
            0x48 => "SMB_COM_GET_PRINT_QUEUE".to_string(),
            0x49 => "SMB_COM_READ_BULK".to_string(),
            0x4A => "SMB_COM_WRITE_BULK".to_string(),
            0x4B => "SMB_COM_WRITE_BULK_DATA".to_string(),
            _ => format!("Unknown SMB command: 0x{:02X}", packet.command),
        }
    }
} 