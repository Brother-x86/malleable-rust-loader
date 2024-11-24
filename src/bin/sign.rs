use log::info;
use malleable_rust_loader::config::Config;
use malleable_rust_loader::initialloader::initialize_loader;
use std::env;
extern crate env_logger;
use argparse::{ArgumentParser, Store};

fn main() {
    env_logger::init();

    let mut keypair = concat!(env!("HOME"), "/.malleable/ed25519.u8").to_string();
    let mut config_file_to_sign: String =
        concat!(env!("HOME"), "/.malleable/config/initial.json").to_string();

    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("sign a configuration with Ed25519 elliptic curbs. by Brother🔥");

        ap.refer(&mut config_file_to_sign).add_argument(
            "config",
            Store,
            "config to sign, default: ~/.malleable/config/initial.json",
        );
        ap.refer(&mut keypair).add_option(&["--keypair"], Store,"path of your private ed25519 key pair to sign configuration, default: ~/.malleable/ed25519.u8)");

        ap.parse_args_or_exit();
    }

    info!("[+] Signing Loader from file: {config_file_to_sign} ");
    let mut loader = Config::new_fromfile(&config_file_to_sign);
    let key_pair = Config::fromfile_master_keypair(keypair.as_str());
    loader.sign_loader(&key_pair);
    info!("[+] Write sign_bytes to: {config_file_to_sign}");
    loader.serialize_to_file_pretty(&config_file_to_sign);
    info!("[+] Done!");
    initialize_loader(loader, config_file_to_sign.to_string());
}
