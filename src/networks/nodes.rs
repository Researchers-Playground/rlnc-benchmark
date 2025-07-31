use rlnc::full::decoder::Decoder;

pub struct Node {
    packet_buffer: Decoder,
}

impl Node {
    pub fn new(packet_buffer: Decoder) -> Self {
        Self { packet_buffer }
    }
}
