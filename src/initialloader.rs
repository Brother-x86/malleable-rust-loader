use crate::dataoperation::DataOperation;
use crate::loaderconf::LoaderConf;

use std::fs;

use crate::dataoperation::apply_all_dataoperations;
use crate::dataoperation::AeadMaterial;

use log::info;
use std::env;


pub fn initialize_loader(loaderconf: LoaderConf, json_file: String) {
    info!("[+] AEAD Encrypt initial loader config");
    let mut dataoperations: Vec<DataOperation> = vec![];
    //TODO multiple time, je comprends pas pk ca fail
    //for n in 1..2 {
    let aead_mat: AeadMaterial = AeadMaterial::init_aead_key_material();
    dataoperations.push(DataOperation::AEAD(aead_mat));

    let mut data: Vec<u8> = loaderconf.concat_loader_jsondata().into_bytes();
    data = apply_all_dataoperations(&mut dataoperations, data).unwrap();

    let path_aead_conf = format!("{json_file}.aead");
    info!("[+] Encrypted loader configuration: {}", path_aead_conf);
    fs::write(&path_aead_conf, &data).expect("Unable to write file");

    let path_aead_material = format!("{json_file}.aead.dataop");
    info!("[+] AEAD material (decryption key): {}", path_aead_material);
    fs::write(
        &path_aead_material,
        serde_json::to_string(&dataoperations).unwrap(),
    )
    .expect("Unable to write file");

    //ROT13 dataoperation of the initial paylaod
    info!("[+] Ofuscate AEAD material with ROT13+BASE64");
    let mut dataoperations: Vec<DataOperation> = vec![DataOperation::ROT13, DataOperation::BASE64];
    let mut data: Vec<u8> = fs::read(format!("{json_file}.aead.dataop")).unwrap();
    data = apply_all_dataoperations(&mut dataoperations, data).unwrap();
    let path_aead_material_rot13b64 = format!("{json_file}.aead.dataop.rot13b64");
    info!(
        "[+] Save ofuscated AEAD material to file: {}",
        path_aead_material_rot13b64
    );
    fs::write(&path_aead_material_rot13b64, &data).expect("Unable to write file");

    // create one config WEBPAGE+BASE64
    let mut data = loaderconf.concat_loader_jsondata().into_bytes();
    data = apply_all_dataoperations(
        &mut vec![DataOperation::WEBPAGE, DataOperation::BASE64],
        data,
    )
    .unwrap();
    let json_file_webp: String = format!("{json_file}.webp");
    info!("[+] Obfuscated WEBPAGE+BASE64 config: {}", json_file_webp);
    fs::write(&json_file_webp, &data).expect("Unable to write file");

    // create one config STEGANO
    let mut data = loaderconf.concat_loader_jsondata().into_bytes();
    // TODO set env variable to 
    // export STEGANO_INPUT_IMAGE=/home/user/.malleable/config/troll2.jpg
    unsafe {
        env::set_var("STEGANO_INPUT_IMAGE", "/home/user/.malleable/config/troll2.jpg");
    }
    data = apply_all_dataoperations(
        &mut vec![DataOperation::STEGANO],
        data,
    )
    .unwrap();
    // TODO, this is useless at this time because output data Vec<u8> are not ok to become an image
    let json_file_steg: String = format!("{json_file}.steg");
    info!("[+] Obfuscated STEGANO config: {}", json_file_steg);
    fs::write(&json_file_steg, &data).expect("Unable to write file");



    


}
