use axum::{http::StatusCode, response::IntoResponse};
use axum::response::Html;
use std::fs;
use axum::http::HeaderMap;
//use serde_json::{Value, Map};

use log::debug;
use log::info;
extern crate env_logger;

//use ring::signature::Ed25519KeyPair;
use ring::signature;
use serde::{Deserialize, Serialize};

// JAVA.exe handler
pub async fn handle_posto(headers: HeaderMap,body: String) -> impl IntoResponse {
    debug!("DATA received raw: {}",&body);
    let webpage: String = "yolo".to_string();
    debug!("[+] response");
    (StatusCode::OK, Html(webpage))

    
}
//https://docs.rs/serde_json/latest/serde_json/value/enum.Value.html#method.sort_all_objects


pub async fn handle_hello() -> impl IntoResponse {
    //let webpage = fs::read_to_string("login.php").unwrap();
    let webpage: String = "yolo".to_string();
    (StatusCode::OK, Html(webpage))
}
