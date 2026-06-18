// ───────────────────────────────────────────────
// Déchiffrement + décompression
// ───────────────────────────────────────────────

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::cipher::block_padding::Pkcs7;
use miniz_oxide::inflate::decompress_to_vec_zlib;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

const CHUNK_SIZE: usize = 64;
const NOISE_SIZE: usize = 8;
const KEY_IV: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../.secrets/key.bin"));

unsafe fn decrypt_payload(data: &[u8]) -> Vec<u8> {
    let key = &KEY_IV[..32];
    let iv  = &KEY_IV[32..];

    let clean = remove_noise(data);

    let decrypted = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&clean)
        .expect("dead");

    decompress_to_vec_zlib(&decrypted)
        .expect("dzlib")
}

fn remove_noise(data: &[u8]) -> Vec<u8> {
    let original_len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(original_len);

    let mut offset = 8;
    while offset < data.len() && out.len() < original_len {
        let remaining = original_len - out.len();
        let chunk_end = (offset + CHUNK_SIZE).min(offset + remaining).min(data.len());
        out.extend_from_slice(&data[offset..chunk_end]);
        offset = chunk_end + NOISE_SIZE;
    }

    out
}


pub fn decrypt(payload: Vec<u8>) -> Vec<u8> {
    println!("Hello, world! decrypt");
    let decrypted = unsafe { decrypt_payload(&payload) };
    return decrypted
}
