//re-export proc macro crate
pub use labyrinth_macros::*;

/// A helper decryption function meant to decrypt encrypted strings at runtime
///
/// # Parameters
/// - `input`: The encrypted string literal
///
pub fn decrypt_string(encrypted: &str) -> String {
    let key = "invalidarray".to_string();
    encrypted
        .chars()
        .zip(key.chars().cycle())
        .map(|(encrypted_char, key_char)| ((encrypted_char as u8) ^ (key_char as u8)) as char)
        .collect()
}
