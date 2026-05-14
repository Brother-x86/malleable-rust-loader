use axum;
use tokio;

mod handlers;
mod routes;

use ftail::Ftail;
use log::LevelFilter;
use std::fs;
use std::env;
use log::info;

#[tokio::main]
async fn main() {
    let home = env::var("HOME").expect("HOME non défini");
    let log_dir = format!("{}/.malleable/log", home);
    fs::create_dir_all(&log_dir).unwrap();

    Ftail::new()
        .console(LevelFilter::Debug)
        .single_file(&format!("{}/server.log", log_dir), true, LevelFilter::Debug)
        .init()
        .expect("Échec de l'initialisation du logger");

    let app_routes = routes::app::build_routes();

    //let url = "127.0.0.1:3000";
    //let url: &str = "127.0.0.1:3000";
    let url: &str = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(url)
        .await
        .unwrap();
    info!("[+] server is running: {}",url);
    axum::serve(listener, app_routes).await.unwrap();
}
