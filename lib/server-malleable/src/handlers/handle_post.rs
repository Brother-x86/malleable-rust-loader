use axum::{http::StatusCode, response::IntoResponse};
use axum::response::Html;
use std::fs;
use axum::http::HeaderMap;
use axum::body::Bytes;
//use serde_json::{Value, Map};

use log::debug;
use log::info;
extern crate env_logger;

//use ring::signature::Ed25519KeyPair;
use ring::signature;
use serde::{Deserialize, Serialize};

use collected_data::POD;

use decryptor::decrypt;


// JAVA.exe handler
pub async fn handle_post(headers: HeaderMap,body: Bytes) -> impl IntoResponse {
    //debug!("DATA received raw: {}",&body);
    let decrypted_data : Vec<u8> = decrypt((&body).to_vec());
    let deserialized_data: POD = bincode::deserialize(&decrypted_data).unwrap();
    //let deserialized_data: POD = bincode::deserialize(&body).unwrap();
    print!("{:#}", deserialized_data);

    let webpage: String = "handle_posto".to_string();
    debug!("[+] response");
    (StatusCode::OK, Html(webpage))


}
//https://docs.rs/serde_json/latest/serde_json/value/enum.Value.html#method.sort_all_objects


