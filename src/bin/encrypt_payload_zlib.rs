use log::info;
use malleable_rust_loader::dataoperation::apply_all_dataoperations;
use malleable_rust_loader::dataoperation::AesMaterial;
use malleable_rust_loader::dataoperation::DataOperation;
use std::fs;
extern crate env_logger;
use argparse::{ArgumentParser, Store};

fn main() {
    env_logger::init();

    let mut payload: String = "".to_string();

    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("encrypt payload with AES, store encrypted payload in a .aes file and the decrypt key in .dataop");

        ap.refer(&mut payload)
            .add_argument("payload", Store, "payload to encrypt");

        ap.parse_args_or_exit();
    }

    let aes_mat: AesMaterial = AesMaterial::generate_aes_material();

    let output_dataop: String = format!("{}{}", payload, ".dataop").to_string();
    let output_payload: String = format!("{}{}", payload, ".aes").to_string();

    let mut dataoperations: Vec<DataOperation> = vec![
        DataOperation::ZLIB,
        DataOperation::AES(aes_mat),
        DataOperation::ZLIB,
    ];

    info!("[+] Payload open {}", payload.as_str());
    let mut data: Vec<u8> = fs::read(payload.as_str()).unwrap();
    info!(
        "[+] Apply dataoperation in reverse order {:?}",
        &dataoperations
    );
    data = apply_all_dataoperations(&mut dataoperations, data).unwrap();

    fs::write(
        output_dataop.as_str(),
        serde_json::to_string(&dataoperations).unwrap(),
    )
    .expect("Unable to write file");
    info!("[+] DataOperation save to file {}", output_dataop.as_str());

    fs::write(output_payload.as_str(), &data).expect("Unable to write file");
    info!("[+] Payload save to file {}", output_payload.as_str());
}
