//! Key derivation and cryptographic helpers for TPM portable credentials.
//!
//! Implements KDFa (SP800-108), KDFe (SP800-56A), AES-128-CFB, and HMAC-SHA256.

use hmac::{KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// KDFe - NIST SP800-56A Concat KDF (used for ECDH seed derivation).
///
/// For 256 bits, this is a single SHA256 block:
/// `SHA256( u32_be(1) || Z || label || partyU || partyV )`
pub fn kdfe(
    z: &[u8],
    label: &[u8],
    party_u: &[u8],
    party_v: &[u8],
    bits: usize,
) -> Zeroizing<Vec<u8>> {
    let klen = bits / 8;
    let mut result = Zeroizing::new(Vec::with_capacity(klen));

    use sha2::Digest;
    let mut counter = 1u32;
    while result.len() < klen {
        let mut hasher = Sha256::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(z);
        hasher.update(label);
        hasher.update(party_u);
        hasher.update(party_v);
        result.extend_from_slice(&hasher.finalize());
        counter += 1;
    }

    result.truncate(klen);
    result
}

/// KDFa - SP800-108 HMAC counter mode (used for symmetric key derivation).
///
/// `blocks = HMAC-SHA256(key, u32_be(counter) || label || 0x00 || contextU || contextV || u32_be(bits))`
pub fn kdfa(
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: usize,
) -> Zeroizing<Vec<u8>> {
    let klen = bits / 8;
    let mut result = Zeroizing::new(Vec::with_capacity(klen));

    type HmacSha256 = hmac::Hmac<Sha256>;

    let mut counter = 1u32;
    while result.len() < klen {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&(bits as u32).to_be_bytes());
        result.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }

    result.truncate(klen);
    result
}

/// AES-128-CFB encryption with zero IV.
///
/// Full-block CFB mode: c[0..16] = p[0..16] XOR AES_encrypt(IV);
/// subsequent blocks XOR AES_encrypt(prev ciphertext block).
pub fn aes_128_cfb_encrypt(key: &[u8], plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
    use aes::Aes128;
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    let cipher = Aes128::new_from_slice(key).expect("valid AES-128 key");
    let mut result = Zeroizing::new(vec![0u8; plaintext.len()]);

    let mut iv = [0u8; 16];
    let block_size = 16;

    for (i, chunk) in plaintext.chunks(block_size).enumerate() {
        let mut block = iv;
        cipher.encrypt_block((&mut block).into());

        let start = i * block_size;
        for (j, &byte) in chunk.iter().enumerate() {
            result[start + j] = byte ^ block[j];
        }

        if chunk.len() == block_size {
            iv.copy_from_slice(&result[start..start + block_size]);
        }
    }

    result
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    type HmacSha256 = hmac::Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::FromHex;
    use sha2::Digest;

    #[test]
    fn kdfe_output_length_matches_requested_bits() {
        let z = [0xAA; 32];
        for bits in [128, 256, 384, 512] {
            let out = kdfe(&z, b"label", b"u", b"v", bits);
            assert_eq!(out.len(), bits / 8);
        }
    }

    #[test]
    fn kdfe_256_matches_single_sha256_block() {
        let z = b"shared_secret_zz";
        let label = b"IDU\0";
        let party_u = b"partyUinfo";
        let party_v = b"partyVinfo";

        let mut hasher = Sha256::new();
        hasher.update(1u32.to_be_bytes());
        hasher.update(z);
        hasher.update(label);
        hasher.update(party_u);
        hasher.update(party_v);
        let expected = hasher.finalize();

        let out = kdfe(z, label, party_u, party_v, 256);
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn kdfe_deterministic_and_sensitive_to_inputs() {
        let z = [0x42; 32];
        let a = kdfe(&z, b"label", b"u", b"v", 256);
        let b = kdfe(&z, b"label", b"u", b"v", 256);
        assert_eq!(a, b);

        let c = kdfe(&z, b"other_label", b"u", b"v", 256);
        assert_ne!(a, c);
    }

    #[test]
    fn kdfa_output_length_matches_requested_bits() {
        let key = [0xBB; 32];
        for bits in [128, 256, 384, 512] {
            let out = kdfa(&key, b"label", b"cu", b"cv", bits);
            assert_eq!(out.len(), bits / 8);
        }
    }

    #[test]
    fn kdfa_256_matches_single_hmac_block() {
        let key = b"derivation_key";
        let label = b"identity\0";
        let context_u = b"contextU";
        let context_v = b"contextV";
        let bits: usize = 256;

        type HmacSha256 = hmac::Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&1u32.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&(bits as u32).to_be_bytes());
        let expected = mac.finalize().into_bytes();

        let out = kdfa(key, label, context_u, context_v, bits);
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn kdfa_deterministic_and_sensitive_to_inputs() {
        let key = [0x11; 32];
        let a = kdfa(&key, b"label", b"cu", b"cv", 256);
        let b = kdfa(&key, b"label", b"cu", b"cv", 256);
        assert_eq!(a, b);

        let c = kdfa(&key, b"label", b"cu", b"cv", 128);
        assert_ne!(&a[..32], &c[..16]);
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected =
            Vec::from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        let out = hmac_sha256(key, data);
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn hmac_sha256_output_length_is_32() {
        let out = hmac_sha256(b"key", b"data");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn hmac_sha256_deterministic_and_sensitive_to_inputs() {
        let a = hmac_sha256(b"key", b"data");
        let b = hmac_sha256(b"key", b"data");
        assert_eq!(a, b);

        let c = hmac_sha256(b"key", b"other");
        assert_ne!(a, c);

        let d = hmac_sha256(b"other_key", b"data");
        assert_ne!(a, d);
    }
}
