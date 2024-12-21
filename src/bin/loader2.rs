#![cfg_attr(not(any(feature = "debug",feature = "info")), windows_subsystem = "windows")]

/* 
#[cfg(feature = "executable")]
use malleable_rust_loader::execmode::executable::run_loader;
*/

#[cfg(feature = "loader")]
use malleable_rust_loader::run_loader;

fn main() {
    // Fonctionnalité commune

    #[cfg(feature = "loader")]
    run_loader();

    // Fonctionnalité spécifique à l'exécutable (activée avec la feature "exe")
    //#[cfg(feature = "exe")]
    //fonctionnalite_executable();
}