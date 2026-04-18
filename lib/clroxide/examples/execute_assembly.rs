use clroxide::clr::Clr;
use std::{env, fs, process::exit};
use obfstr::obfstr;

fn main() -> Result<(), String> {
    let (path, args) = prepare_args();

    let contents = fs::read(path).expect(obfstr!("Unable to read file"));
    let mut clr = Clr::new(contents, args)?;

    let results = clr.run()?;

    println!("{}{}", obfstr!("[*] Results:\n\n"), results);

    Ok(())
}

fn prepare_args() -> (String, Vec<String>) {
    let mut args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("{}", obfstr!("Please provide a path to a dotnet executable"));

        exit(1)
    }

    let mut command_args: Vec<String> = vec![];

    if args.len() > 2 {
        command_args = args.split_off(2)
    }

    let path = args[1].clone();

    println!("{}{}{}{:?}", obfstr!("[+] Running `"), path, obfstr!("` with given args: "), command_args);

    return (path, command_args);
}
