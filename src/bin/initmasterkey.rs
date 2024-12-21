use ring::{rand, signature};
use std::fs;

extern crate env_logger;
use log::info;

//#[allow(dead_code)]
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
    let malleable_working_dir: &str = concat!(env!("HOME"), "/.malleable");
    let keypair_path: &str = concat!(env!("HOME"), "/.malleable/ed25519.u8");
    let payload_dir: &str = concat!(env!("HOME"), "/.malleable/payload");
    let config_dir: &str = concat!(env!("HOME"), "/.malleable/config");

    env_logger::init();
    // TODO create the directory
    fs::create_dir_all(malleable_working_dir).unwrap();
    initialize_master_keypair(keypair_path);
    fs::create_dir_all(payload_dir).unwrap();
    fs::create_dir_all(config_dir).unwrap();
}
