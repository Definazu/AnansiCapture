use http::{Request, Response};
use anyhow::Result;

pub struct HttpProcessor;

impl HttpProcessor {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, payload: &[u8]) -> Result<HttpPacket> {
        // Пробуем разобрать как HTTP запрос
        if let Ok(request) = Request::builder()
            .method("GET")
            .uri("/")
            .body(payload.to_vec())
        {
            return Ok(HttpPacket::Request(request));
        }

        // Пробуем разобрать как HTTP ответ
        if let Ok(response) = Response::builder()
            .status(200)
            .body(payload.to_vec())
        {
            return Ok(HttpPacket::Response(response));
        }

        Err(anyhow::anyhow!("Failed to parse HTTP packet"))
    }
}

pub enum HttpPacket {
    Request(Request<Vec<u8>>),
    Response(Response<Vec<u8>>),
}

impl HttpPacket {
    pub fn get_method(&self) -> String {
        match self {
            HttpPacket::Request(req) => req.method().to_string(),
            HttpPacket::Response(_) => "Response".to_string(),
        }
    }

    pub fn get_path(&self) -> String {
        match self {
            HttpPacket::Request(req) => req.uri().to_string(),
            HttpPacket::Response(res) => res.status().to_string(),
        }
    }

    pub fn get_host(&self) -> String {
        match self {
            HttpPacket::Request(req) => {
                req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("Unknown")
                    .to_string()
            }
            HttpPacket::Response(_) => "Server".to_string(),
        }
    }
} 