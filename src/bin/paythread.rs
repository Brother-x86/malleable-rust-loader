//use malleable_rust_loader::payload::DllFromMemory;
//use malleable_rust_loader::payload::Exec;
use std::{thread, time};
use log::info;
extern crate env_logger;

/* pub enum Job {
    Thread(thread::JoinHandle<()>),
    Spawn(DNSLink),
    FILE(FileLink),
    MEMORY(MemoryLink),
}
*/
use std::process::Command;


fn main() {
    env_logger::init();

    let t1: thread::JoinHandle<()> = thread::spawn(move || {
        thread::sleep(time::Duration::from_millis(500));
    });
    info!("{}",t1.is_finished());
    thread::sleep(time::Duration::from_millis(600));
    info!("{}",t1.is_finished());

    let path: String= "scp".to_string();
    let cmdline: String= "/home/user/.malleable/payload/local_mtls_1080.exe sliver:/tmp/".to_string();

    let mut comm = Command::new(&path);
    for i in cmdline.trim().split_whitespace() {
        comm.arg(i);
    }

    let t2: thread::JoinHandle<()> = thread::spawn(move || {
        thread::sleep(time::Duration::from_millis(500));

    let child: std::process::Child = comm
    .spawn()
    .expect("failed to execute process");
});

    //info!("{:?}",output);
    info!("{}",t2.is_finished());
    thread::sleep(time::Duration::from_millis(10000));
    info!("sleep hello!");
    //info!("{:?}",child.id());
    info!("{}",t2.is_finished());


    //info!("{:?}",child.id());

    /* 
    match child.try_wait() {
        Ok(Some(status)) => println!("exited with: {status}"),
        Ok(None) => {
            println!("status not ready yet, let's really wait");
            let res = child.wait();
            println!("result: {res:?}");
        }
        Err(e) => println!("error attempting to wait: {e}"),
    }
    */
    info!("hello there!");

}