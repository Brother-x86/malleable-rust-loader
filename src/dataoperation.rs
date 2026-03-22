use crate::sttg::{hide_mod, reveal_mod};
use crate::link_noconfig::LinkFetchNoConfig;

use anyhow::{Context, Result};
use base64::prelude::*;
use chksum_sha2_512 as sha2_512;
use flate2::write::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use rand::Rng;
use regex::Regex;
use rot13::rot13;
use serde::{Deserialize, Serialize};
use std::io::Write;
use image::DynamicImage;
use image::ImageFormat;
use std::io::Cursor;

use cryptify::encrypt_string;
use log::debug;

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename = "do")]
pub enum DO {
    #[serde(rename = "bb")]
    BASE64,
    #[serde(rename = "ai")]
    AM(AM),
    #[serde(rename = "WP")]
    WEBPAGE,
    #[serde(rename = "RR")]
    ROT13, // WARNING only after base64 because input is String
    #[serde(rename = "RS")]
    REVERSE,
    #[serde(rename = "sn")]
    STTG(LinkNoConfig),
    #[serde(rename = "ZL")]
    ZLIB,
    #[serde(rename = "S5")]
    SHA512(SHA512),
}

impl DO{
    pub fn name(&self) -> String {
        match self {
            DO::BASE64 => encrypt_string!("base64"),
            DO::AM(_) => encrypt_string!("aes"),
            DO::WEBPAGE=> encrypt_string!("webpage"),
            DO::ROT13 => encrypt_string!("rot13"), // WARNING only after base64 because input is String
            DO::REVERSE => encrypt_string!("reverse"),
            DO::STTG(_)=> encrypt_string!("stegano"),
            DO::ZLIB=> encrypt_string!("zlib"),
            DO::SHA512(_)=> encrypt_string!("sha512"),
        }
    }
}


#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename = "s5")]
pub struct SHA512 {
    #[serde(rename = "hh")]
    pub hash: String,
}
impl SHA512 {
    fn check_sha512(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: SHA512 verify"));
        let digest: chksum_sha2_512::Digest = sha2_512::chksum(data.clone())?;
        let digest_lowercase = digest.to_hex_lowercase();
        if digest_lowercase == self.hash {
            Ok(data)
        } else {
            bail!("Failed to verify SHA512: {}", digest_lowercase)
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
        let re = Regex::new(r"!!!(?<ll>\S+)!!!").unwrap();

        let Some(caps) = re.captures(&haystack) else {
            let e: Result<Vec<u8>, anyhow::Error> = Err(anyhow::Error::msg(encrypt_string!(
                "Failed to harvest WEBPAGE"
            )));
            return e;
        };
        Ok(caps["ll"].as_bytes().to_vec())
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
impl UnApplyDataOperation for DO {
    fn un_apply_one_operation(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            DO::BASE64 => self.base64_decode(data),
            DO::ROT13 => self.rot13_decode(data),
            DO::WEBPAGE => self.webpage_harvesting(data),
            DO::AM(aes_material) => aes_material.decrypt_aes(data),
            DO::STTG(_image_link) => self.stegano_decode_lsb(data),
            DO::ZLIB => self.zlib_decompress(data),
            DO::REVERSE => todo!(),
            DO::SHA512(sha512) => sha512.check_sha512(data),
        }
    }
}

use crate::link_noconfig::LinkNoConfig;
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

    //fn stegano_encode_lsb(&self, data: Vec<u8>, input_image_link:&mut LinkNoConfig, image_output_path:&mut String) -> Result<Vec<u8>, anyhow::Error> {
    fn stegano_encode_lsb(&self, data: Vec<u8>, input_image_link:&LinkNoConfig) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: STEGANO encode"));
        debug!(
            "{}{}",
            encrypt_string!("STEGANO_INPUT_IMAGE: "),            
            serde_json::to_string(&input_image_link).unwrap_or_default()
        );
        let bytes: Vec<u8> = input_image_link.fetch_data_noconfig()?;
        let carrier: DynamicImage = image::load_from_memory_with_format(&bytes, ImageFormat::PNG).unwrap();
        let img: image::ImageBuffer<image::Rgb<u8>, Vec<u8>> = hide_mod(data, carrier);

        let mut output_data = Vec::new();
        DynamicImage::ImageRgb8(img).write_to(&mut Cursor::new(&mut output_data), ImageFormat::PNG)?;
        Ok(output_data)
        //Ok(img.to_vec())
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

impl ApplyDataOperation for DO {
    fn apply_one_operation(&mut self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            DO::BASE64 => self.base64_encode(data),
            DO::ROT13 => self.rot13_encode(data),
            DO::WEBPAGE => self.webpage_create(data),
            DO::AM(aes_material) => aes_material.encrypt_aes(data),
            // AIE AIE AIE
            DO::STTG(image_link) => {
                let image_link_clone = image_link.clone();
                self.stegano_encode_lsb(data, &image_link_clone)},
            //DataOperation::STEGANO(image_link,image_output_path) => todo!(),
            DO::ZLIB => self.zlib_encode(data),
            DO::REVERSE => todo!(),
            DO::SHA512(sha512) => sha512.check_sha512(data),
        }
    }
}

pub fn apply_all_dataoperations(
    data_operations: &mut Vec<DO>,
    mut data: Vec<u8>,
) -> Result<Vec<u8>, anyhow::Error> {
    data_operations.reverse();
    for operation in data_operations {
        data = operation.apply_one_operation(data)?;
    }
    Ok(data)
}

pub fn un_apply_all_dataoperations(
    dataoperation: Vec<DO>,
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

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct AM {
    #[serde(rename = "k")]
    pub key: Vec<u8>,
    #[serde(rename = "n")]
    pub nonce: [u8; 12],
}
impl AM {
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
    pub fn generate_aes_material() -> AM {
        let key: aes_gcm_siv::aead::generic_array::GenericArray<u8, _> =
            Aes256GcmSiv::generate_key(&mut OsRng);
        // 96-bits; unique per message
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill(&mut nonce);
        let nonce_slice: &[u8; 12] = &nonce;
        AM {
            key: key.as_slice().to_owned(),
            nonce: nonce_slice.to_owned(),
        }
    }
}
