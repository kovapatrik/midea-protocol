use base16ct::lower::encode_string as hex_encode;
use bytes::Bytes;
use sha2::{Digest, Sha256};

mod security;

/// Gets the UDP ID for a device. Returns a hex encoded string.
pub fn get_udp_id(device_id_buf: Bytes) -> String {
    let hash = Sha256::digest(device_id_buf);

    let mut output = [0u8; 16];
    for i in 0..16 {
        output[i] = hash[i] ^ hash[i + 16];
    }

    hex_encode(&output)
}
