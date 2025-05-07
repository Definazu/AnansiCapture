use pnet::packet::tcp::{TcpPacket, TcpFlags, TcpOptionNumber};
use pnet::packet::Packet;

pub struct TcpProcessor;

impl TcpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, data: &'a [u8]) -> Option<TcpPacket<'a>> {
        TcpPacket::new(data)
    }

    pub fn get_tcp_flags(flags: u8) -> String {
        let mut result = String::new();
        if flags & TcpFlags::FIN != 0 { result.push('F'); }
        if flags & TcpFlags::SYN != 0 { result.push('S'); }
        if flags & TcpFlags::RST != 0 { result.push('R'); }
        if flags & TcpFlags::PSH != 0 { result.push('P'); }
        if flags & TcpFlags::ACK != 0 { result.push('A'); }
        if flags & TcpFlags::URG != 0 { result.push('U'); }
        if flags & TcpFlags::ECE != 0 { result.push('E'); }
        if flags & TcpFlags::CWR != 0 { result.push('C'); }
        result
    }

    pub fn format_tcp_info(packet: &TcpPacket) -> String {
        let flags = Self::get_tcp_flags(packet.get_flags());
        let seq = packet.get_sequence();
        let ack = packet.get_acknowledgement();
        let win = packet.get_window();
        let len = packet.payload().len();
        
        // Extract timestamp values if present (they are in the options)
        let mut tsval = 0u32;
        let mut tsecr = 0u32;
        
        let options = packet.get_options();
        for option in options {
            if option.number == TcpOptionNumber(8) { // Timestamp option
                if option.data.len() >= 8 {
                    tsval = u32::from_be_bytes([option.data[0], option.data[1], option.data[2], option.data[3]]);
                    tsecr = u32::from_be_bytes([option.data[4], option.data[5], option.data[6], option.data[7]]);
                }
            }
        }

        format!("{} → {} [{}] Seq={} Ack={} Win={} Len={} TSval={} TSecr={}",
            packet.get_source(),
            packet.get_destination(),
            flags,
            seq,
            ack,
            win,
            len,
            tsval,
            tsecr
        )
    }
} 