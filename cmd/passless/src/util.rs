/// Convert bytes to lowercase hexadecimal string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0xff]), "ff");
        assert_eq!(bytes_to_hex(&[0x01, 0x23, 0x45, 0x67]), "01234567");
        assert_eq!(bytes_to_hex(&[0xab, 0xcd, 0xef]), "abcdef");
    }
}
