use loader::lsb_text_png_steganography_mod::reveal_mod;
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <image_path_to_test>", args[0]);
        return;
    }
    let data: Vec<u8> = fs::read(&args[1]).unwrap();
    let hidd = reveal_mod(data).unwrap();
    println!("hidd= {:?}",&hidd);
    println!("to string= {:?}",String::from_utf8_lossy(&hidd));
}