use anyhow::Result;

pub struct DnsProcessor;

impl DnsProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process<'a>(&self, payload: &'a [u8]) -> Result<dns_parser::Packet<'a>> {
        dns_parser::Packet::parse(payload)
            .map_err(|e| anyhow::anyhow!("Failed to parse DNS packet: {}", e))
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