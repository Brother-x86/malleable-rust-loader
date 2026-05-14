use obfstr::obfstr;
use serde::{Deserialize, Serialize};

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
        write!(f, "{}", obfstr!("POD Info:\n"))?;
        write!(f, "{:<20} {}\n", obfstr!("Session ID:"),          self.session_id)?;
        write!(f, "{:<20} {}\n", obfstr!("Hostname:"),            self.hostname)?;
        write!(f, "{:<20} {}\n", obfstr!("Username:"),            self.username)?;
        write!(f, "{:<20} {}\n", obfstr!("Domain:"),              self.domain)?;
        write!(f, "{:<20} {}\n", obfstr!("Architecture:"),        self.arch)?;
        write!(f, "{:<20} {}\n", obfstr!("Distribution:"),        self.distro)?;
        write!(f, "{:<20} {}\n", obfstr!("Desktop Environment:"), self.desktop_env)?;
        write!(f, "{:<20} {}\n", obfstr!("Command Line:"),        self.cmdline)?;
        write!(f, "{:<20} {}\n", obfstr!("Working Directory:"),   self.working_dir)?;
        write!(f, "{:<20} {}\n", obfstr!("Process Path:"),        self.process_path)?;
        write!(f, "{:<20} {}\n", obfstr!("Process Name:"),        self.process_name)?;
        write!(f, "{:<20} {}\n", obfstr!("PID:"),                 self.pid)?;
        write!(f, "{:<20} {}\n", obfstr!("Parent Name:"),         self.parent_name)?;
        write!(f, "{:<20} {}\n", obfstr!("PPID:"),                self.ppid)?;
        write!(f, "{:<20} {}\n", obfstr!("Total Memory:"),        self.total_memory)?;
        write!(f, "{:<20} {}\n", obfstr!("Used Memory:"),         self.used_memory)?;
        write!(f, "{:<20} {}\n",   obfstr!("CPU Count:"),         self.nb_cpu)
    }
}