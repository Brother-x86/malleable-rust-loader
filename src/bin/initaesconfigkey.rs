use loader::dataoperation::AM;
use loader::dataoperation::DO;
use std::fs;

extern crate env_logger;
use log::info;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    info!("[+] GENERATE aes key to encrypt all config");

    let aeskey_path: String = format!("{}{}",env!("HOME"), "/.malleable/config/config.aes");
    let aes_mat: AM = AM::generate_aes_material();

    let dataop: DO = DO::AM(aes_mat);
    fs::write(
        &aeskey_path,
        serde_json::to_string(&dataop).unwrap(),
    )
    .expect("Unable to write file");
    info!("[+] AES key save to file {}", aeskey_path.as_str());
}
