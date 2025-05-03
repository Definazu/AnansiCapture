use pnet::packet::tcp::{TcpPacket, TcpFlags};

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
} 