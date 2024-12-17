use malleable_rust_loader::dataoperation::DataOperation;
use std::fs;

fn main() {
    let dataop = vec![
        DataOperation::BASE64,
        DataOperation::ZLIB,
        DataOperation::BASE64,
    ];
    fs::write(
        concat!(env!("HOME"), "/.malleable/config/server.dataop"),
        serde_json::to_string(&dataop).unwrap(),
    )
    .expect("yolo");
}
