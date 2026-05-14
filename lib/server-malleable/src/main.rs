use axum;
use tokio;

mod handlers;
mod routes;

mod dataoperation;


use ftail::Ftail;
use log::LevelFilter;
use std::fs;
use log::info;


#[tokio::main]
async fn main() {
    let log_path: &str = "/root/.malleable/log/";
    let info = &format!("{}/info",log_path);
    let error = &format!("{}/error",log_path);
    let debug = &format!("{}/debug",log_path);
    fs::create_dir_all(info).unwrap();
    fs::create_dir_all(error).unwrap();
    fs::create_dir_all(debug).unwrap();


    Ftail::new()
    .console(LevelFilter::Info)
    .daily_file(info, LevelFilter::Info)
    .daily_file(error, LevelFilter::Error)
    .daily_file(debug, LevelFilter::Debug)
    .init().unwrap();

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
