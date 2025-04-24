use async_trait::async_trait;
use tokio::sync::mpsc;
use pcap::Packet;

#[async_trait]
pub trait PacketObserver: Send + Sync {
    async fn on_packet_received(&self, packet: Packet);
}

pub struct ChannelPacketObserver {
    sender: mpsc::Sender<Packet<'static>>,
}

impl ChannelPacketObserver {
    pub fn new(sender: mpsc::Sender<Packet<'static>>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl PacketObserver for ChannelPacketObserver {
    async fn on_packet_received(&self, packet: Packet) {
        let _ = self.sender.send(packet).await;
    }
}