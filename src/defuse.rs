use gethostname::gethostname;
use log::debug;
#[cfg(target_os = "windows")]
use log::error;
use log::warn;
use serde::{Deserialize, Serialize};
use std::env;

use crate::link::{HTTPLink, Link, LinkFetch};
use cryptify::encrypt_string;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Defuse {
    Hostname(Hostname),
    Env(Env),
    DomainJoin(DomainJoin),
    CheckInternet(CheckInternet),
}
impl Defuse {
    pub fn stop_the_exec(&self) -> bool {
        match self {
            Defuse::Hostname(hostname) => hostname.stop_exec(),
            Defuse::DomainJoin(domain_join) => domain_join.stop_exec(),
            Defuse::CheckInternet(checkinternet) => checkinternet.stop_exec(),
            Defuse::Env(env_variable) => env_variable.stop_exec(),
        }
    }
    pub fn get_operator(&self) -> Operator {
        match self {
            Defuse::Hostname(hostname) => hostname.get_operator(),
            Defuse::DomainJoin(domain_join) => domain_join.get_operator(),
            Defuse::CheckInternet(checkinternet) => checkinternet.get_operator(),
            Defuse::Env(env_variable) => env_variable.get_operator(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Operator {
    AND,
    OR,
}

pub trait DefuseCheck {
    fn stop_exec(&self) -> bool;
    fn get_operator(&self) -> Operator;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckInternet {
    pub list: Vec<String>,
    pub operator: Operator,
}
impl DefuseCheck for CheckInternet {
    fn stop_exec(&self) -> bool {
        for url in &self.list {
            debug!("{}{}", encrypt_string!("check internet: "), url);
            let link: Link = Link::HTTP(HTTPLink {
                url: url.to_string(),
                dataoperation: vec![],
                jitt: 0,
                sleep: 0,
            });
            match link.fetch_data() {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hostname {
    pub list: Vec<String>,
    pub operator: Operator,
}
impl DefuseCheck for Hostname {
    fn stop_exec(&self) -> bool {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Env {
    pub var: String,
    pub value: String,
    pub operator: Operator,
}
impl DefuseCheck for Env {
    fn stop_exec(&self) -> bool {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DomainJoin {
    pub list: Vec<String>,
    pub operator: Operator,
}

#[cfg(target_os = "linux")]
impl DefuseCheck for DomainJoin {
    fn stop_exec(&self) -> bool {
        true
    }
    fn get_operator(&self) -> Operator {
        self.operator
    }
}

#[cfg(target_os = "windows")]
impl DefuseCheck for DomainJoin {
    fn stop_exec(&self) -> bool {
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
