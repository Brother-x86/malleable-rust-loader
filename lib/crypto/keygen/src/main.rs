use rand::RngCore;
use std::fs;
use std::path::Path;

fn main() {
    let secrets_dir = Path::new("/../.secrets");

    // Crée le dossier s'il n'existe pas
    if !secrets_dir.exists() {
        fs::create_dir_all(secrets_dir).expect("Impossible de créer .secrets/");
        println!("[*] Dossier .secrets/ créé");
    }

    let key_path = secrets_dir.join("key.bin");

    let mut rng = rand::thread_rng();

    // AES-256 → clé 32 bytes + IV 16 bytes = 48 bytes total
    let mut key_iv = [0u8; 48];
    rng.fill_bytes(&mut key_iv);

    fs::write(&key_path, &key_iv).expect("Impossible d'écrire key.bin");

    println!("[+] Clé AES-256 + IV générés dans .secrets/key.bin");
    println!("    Key : {}", hex(&key_iv[..32]));
    println!("    IV  : {}", hex(&key_iv[32..]));
    //println!("[!] Ne commitez JAMAIS ce fichier !");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
