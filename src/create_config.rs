use crate::config::CCC;
use crate::dataoperation::apply_all_dataoperations;
use crate::dataoperation::AM;
use crate::dataoperation::DO;
use crate::link::LF;
use crate::link::LinkFetch;

use std::fs;

use log::debug;
use log::info;

pub fn encrypt_config(config: CCC, json_config_file: String) {
    let message = "Unable to write file";
    let decrypt_file = format!("{}.encrypted", json_config_file);

    let mut dataoperations: Vec<DO> = vec![];
    let aes_mat: AM = AM::generate_aes_material();
    dataoperations.push(DO::AM(aes_mat));

    let mut data: Vec<u8> = config.concat_loader_jsondata().into_bytes();
    data = apply_all_dataoperations(&mut dataoperations, data).unwrap();

    let path_aes_conf = format!("{decrypt_file}.aes");
    info!("[+] AES encrypted loader config: {}", path_aes_conf);
    fs::write(&path_aes_conf, &data).expect(message);

    let path_aes_material = format!("{decrypt_file}.aes.dataop");
    info!("[+] AES decryption key material: {}", path_aes_material);
    fs::write(
        &path_aes_material,
        serde_json::to_string(&dataoperations).unwrap(),
    )
    .expect(message);

    // Ofuscate AES material with ROT13+BASE64
    let mut dataoperations: Vec<DO> = vec![
        DO::ROT13,
        DO::BASE64,
        DO::ZLIB,
    ];

    let mut data: Vec<u8> = fs::read(format!("{decrypt_file}.aes.dataop")).unwrap();
    data = apply_all_dataoperations(&mut dataoperations, data).unwrap();
    let path_aes_material_obfuscated = format!("{decrypt_file}.aes.dataop.obfuscated");
    info!(
        "[+] AES decryption key obfuscated with {}: {}",
        serde_json::to_string(&dataoperations).unwrap_or_default(), path_aes_material_obfuscated
    );
    fs::write(&path_aes_material_obfuscated, &data).expect(message);

    //NEW!

    let path_aes_material_obfuscated_dataop =
        format!("{decrypt_file}.aes.dataop.obfuscated.dataop");
    dataoperations.reverse();
    let mut obfuscated_dataop_zlib = serde_json::to_vec(&dataoperations).unwrap();
    let mut zlib_dataop: Vec<DO> = vec![DO::ZLIB];
    obfuscated_dataop_zlib =
        apply_all_dataoperations(&mut zlib_dataop, obfuscated_dataop_zlib).unwrap();
    fs::write(&path_aes_material_obfuscated_dataop, obfuscated_dataop_zlib).expect(message);
    info!(
        "[+] AES decryption key de-obfuscation steps: {}",
        path_aes_material_obfuscated_dataop
    );
}


pub fn collect_all_data_operation(config: &CCC) -> Vec<Vec<DO>> {
    let mut dataope_list: Vec<Vec<DO>> = vec![];
    for (_pool_nb, (_pool_name, pool)) in config.update_links.clone() {
        for update_link in pool.pool_links {
            let dataope = update_link.get_dataoperation();
            if dataope_list.contains(&dataope) == false {
                dataope_list.push(dataope);
            }
        }
    }
    return dataope_list;
}

pub fn create_extension_filename(dataop: &Vec<DO>) -> String {
    let mut extension_file_name = "".to_string();
    let end_with_stegano: bool = matches!(dataop.first(), Some(DO::STTG(_)));

    let mut data_op_reverse=dataop.clone();
    data_op_reverse.reverse();
    for onedataop in data_op_reverse {
        extension_file_name=format!("{}.{}",extension_file_name,&onedataop.name());
    };
    
    if end_with_stegano {
        format!("{}.png",extension_file_name)
    }else{
        extension_file_name
    }
}

pub fn initialize_all_configs(config: CCC, json_config_file: String) {
    encrypt_config(config.clone(), json_config_file.clone());
    let dataope_list = collect_all_data_operation(&config);
    debug!("Data operation list for Config: {}", serde_json::to_string(&dataope_list).unwrap_or_default());
    for dataop in dataope_list {
        let output_filepath   =  format!("{}{}{}",env!("HOME"), "/.malleable/config/initial.json",create_extension_filename(&dataop) );
 
        let mut output_filelink:LF = LF{
            file_path: output_filepath,
            dataoperation: dataop,
            jitt: 0,
            sleep: 0,
        };

        debug!("output_filelink: {}",serde_json::to_string(&output_filelink).unwrap_or_default());
        config.backup_config_to_file(&mut output_filelink);
    }
}

