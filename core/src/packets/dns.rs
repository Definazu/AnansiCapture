use anyhow::Result;
use dns_parser::{Packet, ResponseCode};

pub struct DnsProcessor;

impl DnsProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, payload: &'a [u8]) -> Result<Packet<'a>> {
        Packet::parse(payload)
            .map_err(|e| anyhow::anyhow!("Failed to parse DNS packet: {}", e))
    }

    pub fn get_query_info(&self, packet: &Packet) -> String {
        let mut info = String::new();
        
        // Добавляем тип запроса (query/response)
        if packet.header.query {
            info.push_str("Standard query ");
        } else {
            info.push_str("Standard query response ");
        }
        
        // Добавляем ID запроса
        info.push_str(&format!("0x{:04x} ", packet.header.id));
        
        // Добавляем информацию о запросе
        if let Some(question) = packet.questions.first() {
            info.push_str(&format!("{} ", question.qname));
            info.push_str(&format!("{:?}", question.qtype));
        }
        
        // Добавляем информацию об ответах
        if !packet.header.query && !packet.answers.is_empty() {
            info.push_str(" ");
            for answer in &packet.answers {
                info.push_str(&format!("{:?} ", answer.data));
            }
        }
        
        // Добавляем информацию о CNAME
        if !packet.header.query && !packet.nameservers.is_empty() {
            for ns in &packet.nameservers {
                if let dns_parser::RData::CNAME(cname) = &ns.data {
                    info.push_str(&format!("CNAME {:?} ", cname));
                }
            }
        }
        
        // Добавляем код ответа, если есть ошибка
        if packet.header.response_code != ResponseCode::NoError {
            info.push_str(&format!("RCode: {:?}", packet.header.response_code));
        }
        
        info
    }

    pub fn get_query_type(&self, packet: &dns_parser::Packet) -> String {
        if let Some(question) = packet.questions.first() {
            format!("{:?}", question.qtype)
        } else {
            "No query".to_string()
        }
    }

    pub fn get_answer_type(&self, packet: &dns_parser::Packet) -> String {
        if let Some(answer) = packet.answers.first() {
            format!("{:?}", answer.data)
        } else {
            "No answer".to_string()
        }
    }
} 