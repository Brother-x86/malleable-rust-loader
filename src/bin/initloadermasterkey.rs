use log::info;
use ring::{rand, signature};
use std::fs;
extern crate env_logger;

#[allow(dead_code)]
fn initialize_master_keypair(path_file: &str) {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    info!("pkcs8_bytes = {:?}", pkcs8_bytes.as_ref());
    fs::write(path_file, pkcs8_bytes.as_ref()).expect("Unable to write file");
    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    info!("key_pair = {:?}", key_pair);
}

fn main() {
    let keypair_path: &str = concat!(env!("HOME"), "/.malleable/config/ed25519.u8");

    env_logger::init();
    // TODO create the directory
    initialize_master_keypair(keypair_path);
}
