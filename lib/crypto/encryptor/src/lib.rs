use aes::Aes256;
use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;

// Taille des chunks entre lesquels on insère du bruit
const CHUNK_SIZE: usize = 64;
// Taille du bruit inséré entre chaque chunk (fixe pour simplifier le décodage)
const NOISE_SIZE: usize = 8;

const KEY_IV: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../.secrets/key.bin"));


pub fn encrypt(payload: Vec<u8>) -> Vec<u8> {
    // 1. Lit la clé
    let key_iv: Vec<u8> = KEY_IV.to_vec();

    let key = &key_iv[..32];
    let iv  = &key_iv[32..];

    // 2. Lit le payload
    //let payload: Vec<u8> = b"toto".to_vec();
    println!("[*] Payload lu        : {} bytes", payload.len());

    // 3. Compresse avec zlib
    let compressed = compress_zlib(&payload);
    println!("[*] Après compression : {} bytes ({:.1}%)",
        compressed.len(),
        compressed.len() as f64 / payload.len() as f64 * 100.0
    );

    // 4. Chiffre AES-256 CBC
    let encrypted = Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(&compressed);
    println!("[*] Après chiffrement : {} bytes", encrypted.len());

    // 5. Disperse du bruit pour casser l'entropie uniforme
    let noisy = add_noise(&encrypted);
    println!("[*] Après bruit       : {} bytes (+{} bytes)",
        noisy.len(),
        noisy.len() - encrypted.len()
    );

    // 6. Sauve le résultat : même nom + .packed
    //let out_path = format!("{}.packed", payload_path);
    //fs::write(&out_path, &noisy).expect("Impossible d'écrire le fichier packé");
    //println!("[+] Fichier packé sauvé : {}", out_path);
    println!("[+] Terminé encrypt !");
    return noisy;
}

fn compress_zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).expect("Erreur compression");
    encoder.finish().expect("Erreur finalisation compression")
}

/// Insère NOISE_SIZE bytes aléatoires tous les CHUNK_SIZE bytes.
/// Le loader connaît CHUNK_SIZE et NOISE_SIZE → peut reconstituer les données.
/// Format final : [u64 taille originale] [chunks entrelacés de bruit]
fn add_noise(data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::new();

    // Préfixe : taille des données chiffrées sur 8 bytes (little-endian)
    // Le loader en a besoin pour savoir où s'arrêter
    let len = data.len() as u64;
    out.extend_from_slice(&len.to_le_bytes());

    let mut offset = 0;
    while offset < data.len() {
        // Chunk de données réelles
        let end = (offset + CHUNK_SIZE).min(data.len());
        out.extend_from_slice(&data[offset..end]);
        offset = end;

        // Bruit aléatoire (même en fin de données pour uniformiser)
        let mut noise = [0u8; NOISE_SIZE];
        rng.fill_bytes(&mut noise);
        out.extend_from_slice(&noise);
    }

    out
}
