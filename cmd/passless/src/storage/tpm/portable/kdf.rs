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
