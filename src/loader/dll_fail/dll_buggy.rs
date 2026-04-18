use crate::run_loader;

// this is all entrypoint of the DLL, you should modified this to feet your need (its not OPSEC actually)

#[no_mangle]
pub extern "system" fn Kaboum() {
    run_loader();
}
/* 
#[no_mangle]
pub extern "system" fn Overlord() {
    run_loader();
}
*/
#[no_mangle]
pub extern "system" fn Void() {
    run_loader();
}
#[no_mangle]
pub extern "system" fn MicroTech() {
    run_loader();
}
#[no_mangle]
pub extern "system" fn MiliTech() {
    run_loader();
}


// ya vraiment un probleme avec les thread dans le DllMain
// idea: gerer son propre system de Thread.

use winapi::shared::minwindef;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::LPVOID;
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use obfstr::obfstr;

// TODO only if DllMain compilation option
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    const DLL_PROCESS_ATTACH: DWORD = 1;
    const DLL_PROCESS_DETACH: DWORD = 0;
    const DLL_THREAD_ATTACH: DWORD = 2;
    const DLL_THREAD_DETACH: DWORD = 3;

    unsafe {
        DisableThreadLibraryCalls(dll_module);
    }

    if call_reason == DLL_PROCESS_ATTACH {
        println!("{}", obfstr!("DLL_PROCESS_ATTACH"));
        //run_loader();
    } else if call_reason == DLL_PROCESS_DETACH {
        println!("{}", obfstr!("DLL_PROCESS_DETACH"));
    } else if call_reason == DLL_THREAD_ATTACH {
        println!("{}", obfstr!("DLL_THREAD_ATTACH"));
    } else if call_reason == DLL_THREAD_DETACH {
        println!("{}", obfstr!("DLL_THREAD_DETACH"));
    } else {
        println!("{}", obfstr!("Valeur inconnue"));
    };

    minwindef::TRUE
}

