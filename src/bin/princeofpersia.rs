#![cfg_attr(
    not(any(feature = "debug", feature = "info", feature = "visible")),
    windows_subsystem = "windows"
)]

#[cfg(feature = "loader")]
use princeofpersia::run_loader;

fn main() {
    #[cfg(feature = "loader")]
    run_loader();
}
