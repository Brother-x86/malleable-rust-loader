use sysinfo::{System, Pid};
use std::env;
use std::process;


pub fn working_dir() -> String {
    match env::current_dir() {
        Ok(path) =>  path.display().to_string(),
        Err(_) => "".to_string(),
    }}
pub fn cmdline() -> String {
    let args: Vec<String> = env::args().collect();
    args.join(" ")
}

#[cfg(target_os = "linux")]
pub fn get_domain_name() -> String {
    "".to_string()
}

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    Networking::ActiveDirectory::{DsGetDcNameA, DOMAIN_CONTROLLER_INFOA},
};

#[cfg(target_os = "windows")]
pub fn get_domain_name() -> String {
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
            return "".to_string();
        }

        let domain_name = unsafe { (*domain_controller_info).DomainName };
        let domain_name_str = unsafe { std::ffi::CStr::from_ptr(domain_name as _).to_str().unwrap().to_string() } ;
        domain_name_str
}

pub fn process_name_and_parent(sys: &System) -> (String,String,u32) {
    let process_name:String;
    let parent_name:String;
    let ppid:u32;
    if let Some(p) = sys.process(Pid::from_u32(process::id())) {
        process_name =p.name().to_string();
        if let Some(pp) = p.parent() {
            if let Some(pparent) = sys.process(pp){
                parent_name= pparent.name().to_string();
                ppid=pp.as_u32();
            }else{
                parent_name="".to_string();
                ppid=0;
            }
        }else{
            parent_name="".to_string();
            ppid=0;
        }
    } else {
        process_name = "".to_string();
        parent_name = "".to_string();
        ppid=0;
    };
    (process_name,parent_name,ppid)
}

pub fn process_path() -> String {
    let process_path: String = match env::current_exe(){
        Ok(ppp) => ppp.to_string_lossy().to_string(),
        Err(_) => "".to_string()
    };
    process_path
}

/* 
*/

pub fn bytes_to_gigabytes(bytes: u64) -> f64 {
    const BYTES_IN_GIGABYTE: u64 = 1024 * 1024 * 1024; // 1 GB en octets
    bytes as f64 / BYTES_IN_GIGABYTE as f64
}

pub fn bytes_to_gigabytes_string( bytes: u64) -> String{
    format!("{:.2} Go", bytes_to_gigabytes(bytes))

}

