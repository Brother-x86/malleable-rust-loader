use std::fs::File;
use std::io::prelude::*;

pub fn get_file_string<'a>(file_path: &'a str) -> String {
    let mut f = File::open(file_path).expect("file not found");

    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("something went wrong reading the file");

    contents
}
