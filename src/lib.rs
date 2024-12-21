pub mod config;
pub mod create_config;
pub mod dataoperation;
pub mod defuse;
pub mod link;
pub mod link_util;
pub mod lsb_text_png_steganography_mod;
pub mod payload;
pub mod payload_util;
pub mod poollink;
pub mod python_embedder;


// Module regroupant les fonctionnalités
pub mod execmode {
    //pub mod commune;

    #[cfg(feature = "loader")]
    pub mod executable;
    //pub mod bibliotheque;

    pub mod dll;

}

// Rendre les fonctionnalités accessibles directement
//pub use featexecmodeures::commune::fonctionnalite_commune;

#[cfg(feature = "loader")]
pub use execmode::executable::run_loader;
//pub use execmode



/*
#[cfg(feature = "dll")]
#[cfg(feature = "loader")]
#[no_mangle]  // Empêche le compilateur de modifier le nom de la fonction (mangling)
pub extern "C" fn DllInstall() {
    println!("Running loader from DLL!");
    run_loader()
}
 */


 /*

#[cfg(feature = "dll")]
#[cfg(feature = "loader")]
use windows::{Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK}, Win32::System::SystemServices::*,};

#[cfg(feature = "dll")]
#[cfg(feature = "loader")]
use windows::core::s;

#[cfg(feature = "dll")]
#[cfg(feature = "loader")]
#[no_mangle]
#[allow(non_snake_case)]
//pub extern "C" fn DllInstall() {
fn DllInstall(_: usize, dw_reason: u32, _: usize) -> i32 {
    match dw_reason {
        DLL_PROCESS_ATTACH => attach(),
        _ => (),
    }

    1
}

#[cfg(feature = "dll")]
#[cfg(feature = "loader")]
fn attach() {
    unsafe {
        MessageBoxA(None, s!("Hello from Rust DLL"), s!("Hello from Rust DLL"), MB_OK);
    }
}

     */
