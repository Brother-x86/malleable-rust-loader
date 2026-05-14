use axum::{http::StatusCode, response::IntoResponse};
use axum::response::Html;
use std::fs;
use axum::http::HeaderMap;
//use serde_json::{Value, Map};

use log::debug;
use log::info;
extern crate env_logger;

pub async fn handle_get() -> impl IntoResponse {
    //let webpage = fs::read_to_string("login.php").unwrap();
    let webpage: String = "yolo".to_string();
    (StatusCode::OK, Html(webpage))
}
