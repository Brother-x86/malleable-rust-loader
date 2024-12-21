use windows::{Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK}, Win32::System::SystemServices::*,};
use windows::core::s;
use crate::run_loader;

//https://fluxsec.red/rust-dll-windows-api
//TODO: https://blog.nviso.eu/2020/08/04/debugging-dlls-3-techniques-to-help-you-get-started/

// cargo build --target x86_64-pc-windows-gnu  --features info  --features loader --lib --features dll

#[no_mangle]
#[allow(non_snake_case)]
fn DllMain(_: usize, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        DLL_PROCESS_ATTACH => attach(),
        _ => (),
    }
    1
}

fn attach() {
    unsafe {
        MessageBoxA(None, s!("Hello from MALLEABLE"), s!("MALLEABLE"), MB_OK);
        run_loader();
    }
}