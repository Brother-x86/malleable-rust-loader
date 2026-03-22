use loader::dataoperation::DO;

use std::fs;

fn main() {
    let dataop = vec![
        DO::BASE64,
        DO::ZLIB,
        DO::BASE64,
    ];
    fs::write(
        concat!(env!("HOME"), "/.malleable/config/server.dataop"),
        serde_json::to_string(&dataop).unwrap(),
    )
    .expect("yolo");
}
