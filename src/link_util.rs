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
