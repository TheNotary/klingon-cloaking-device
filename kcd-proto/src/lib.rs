/// Default UDP port for the knock listener.
pub const DEFAULT_KNOCK_PORT: u16 = 9000;

/// Default TCP port for the TLS auth listener.
pub const DEFAULT_AUTH_PORT: u16 = 9001;

/// Protocol version for knock packets.
pub const PROTOCOL_VERSION: u8 = 1;

/// Default number of chunks to split the knock password into.
pub const DEFAULT_KNOCK_CHUNKS: u8 = 4;

/// Seconds a knock sequence remains valid (replay protection).
pub const KNOCK_WINDOW_SECS: u64 = 30;

/// Seconds the TCP accept window stays open after a successful knock.
pub const TCP_ACCEPT_WINDOW_SECS: u64 = 30;

/// Minimum knock packet size: version(1) + seq(1) + total(1) + timestamp(8) = 11 bytes.
const HEADER_SIZE: usize = 11;

/// Maximum payload bytes accepted for a single knock packet.
///
/// Ethernet MTU is commonly 1500 bytes. With UDP/IP overhead and our 11-byte
/// header, 1024 bytes keeps packets well below practical path limits and avoids
/// allocating unbounded payloads from untrusted input.
pub const MAX_KNOCK_PAYLOAD_SIZE: usize = 1024;

/// A single knock packet in the port-knock sequence.
///
/// Wire format (big-endian):
/// ```text
/// [version: u8][seq: u8][total: u8][timestamp: u64 BE][payload: remaining bytes]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnockPacket {
    pub version: u8,
    pub seq: u8,
    pub total: u8,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

impl KnockPacket {
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.push(self.version);
        buf.push(self.seq);
        buf.push(self.total);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize from wire format. Returns `None` on invalid data.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_SIZE {
            return None;
        }
        let version = data[0];
        if version != PROTOCOL_VERSION {
            return None;
        }
        let seq = data[1];
        let total = data[2];
        if total == 0 || seq >= total {
            return None;
        }
        let timestamp = u64::from_be_bytes(data[3..11].try_into().ok()?);
        let payload_len = data.len().checked_sub(HEADER_SIZE)?;
        if payload_len > MAX_KNOCK_PAYLOAD_SIZE {
            return None;
        }

        let payload = data[HEADER_SIZE..].to_vec();
        Some(Self {
            version,
            seq,
            total,
            timestamp,
            payload,
        })
    }
}

/// Split a password into `chunks` roughly equal parts for the knock sequence.
pub fn split_knock(password: &[u8], chunks: u8) -> Vec<Vec<u8>> {
    let n = chunks as usize;
    if n == 0 {
        return vec![];
    }
    let base_len = password.len() / n;
    let remainder = password.len() % n;
    let mut result = Vec::with_capacity(n);
    let mut offset = 0;
    for i in 0..n {
        let chunk_len = base_len + if i < remainder { 1 } else { 0 };
        result.push(password[offset..offset + chunk_len].to_vec());
        offset += chunk_len;
    }
    result
}

/// Reassemble chunks (ordered by index) back into the original password bytes.
pub fn assemble_knock(chunks: &[Vec<u8>]) -> Vec<u8> {
    chunks.iter().flat_map(|c| c.iter().copied()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip() {
        let pkt = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: 2,
            total: 4,
            timestamp: 1_700_000_000,
            payload: b"hello".to_vec(),
        };
        let bytes = pkt.to_bytes();
        let decoded = KnockPacket::from_bytes(&bytes).expect("should decode");
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn packet_rejects_short_data() {
        assert!(KnockPacket::from_bytes(&[0u8; 5]).is_none());
    }

    #[test]
    fn packet_rejects_wrong_version() {
        let mut pkt = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: 0,
            total: 1,
            timestamp: 1,
            payload: vec![],
        };
        pkt.version = 99;
        let bytes = pkt.to_bytes();
        assert!(KnockPacket::from_bytes(&bytes).is_none());
    }

    #[test]
    fn packet_rejects_seq_ge_total() {
        let pkt = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: 4,
            total: 4,
            timestamp: 1,
            payload: vec![],
        };
        let bytes = pkt.to_bytes();
        assert!(KnockPacket::from_bytes(&bytes).is_none());
    }

    #[test]
    fn packet_rejects_zero_total() {
        let mut bytes = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: 0,
            total: 1,
            timestamp: 1,
            payload: vec![],
        }
        .to_bytes();
        bytes[2] = 0; // total = 0
        assert!(KnockPacket::from_bytes(&bytes).is_none());
    }

    #[test]
    fn packet_empty_payload() {
        let pkt = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: 0,
            total: 1,
            timestamp: 42,
            payload: vec![],
        };
        let bytes = pkt.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let decoded = KnockPacket::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload, Vec::<u8>::new());
    }

    #[test]
    fn split_and_assemble_round_trip() {
        let password = b"mysecretpassword123";
        let chunks = split_knock(password, 4);
        assert_eq!(chunks.len(), 4);
        let reassembled = assemble_knock(&chunks);
        assert_eq!(reassembled, password);
    }

    #[test]
    fn split_uneven_lengths() {
        let password = b"12345"; // 5 bytes into 3 chunks: 2, 2, 1
        let chunks = split_knock(password, 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], b"12");
        assert_eq!(chunks[1], b"34");
        assert_eq!(chunks[2], b"5");
        assert_eq!(assemble_knock(&chunks), password);
    }

    #[test]
    fn split_single_chunk() {
        let password = b"abc";
        let chunks = split_knock(password, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], b"abc");
    }

    #[test]
    fn split_empty_password() {
        let chunks = split_knock(b"", 4);
        assert_eq!(chunks.len(), 4);
        assert!(chunks.iter().all(|c| c.is_empty()));
        assert_eq!(assemble_knock(&chunks), b"");
    }

    #[test]
    fn split_zero_chunks() {
        let chunks = split_knock(b"abc", 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn packet_rejects_oversized_payload() {
        let mut bytes = KnockPacket {
            version: PROTOCOL_VERSION,
            seq: 0,
            total: 1,
            timestamp: 1,
            payload: vec![0u8; MAX_KNOCK_PAYLOAD_SIZE + 1],
        }
        .to_bytes();

        bytes[0] = PROTOCOL_VERSION;
        assert!(KnockPacket::from_bytes(&bytes).is_none());
    }
}
