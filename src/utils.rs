use rand::Rng;
use regex::Regex;
use std::path::PathBuf;
use log::debug;

fn generate_random_hex(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| format!("{:x}", rng.gen_range(0..16)))
        .collect()
}

fn generate_random_int(n: usize) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let max = 10u64.pow(n as u32);
    let mut rng = rand::thread_rng();
    let num = rng.gen_range(0..max);
    format!("{:0width$}", num, width = n) // avec padding pour garder N chiffres
}

fn replace_patterns(input: String) -> String {
    let re = Regex::new(r"\$\{(RANDOMHEX|RANDOMINT):(\d+)\}").unwrap();
    re.replace_all(&input, |caps: &regex::Captures| {
        let kind = &caps[1];
        let len: usize = caps[2].parse().unwrap_or(1);

        match kind {
            "RANDOMHEX" => generate_random_hex(len),
            "RANDOMINT" => generate_random_int(len),
            _ => caps[0].to_string(), // fallback: ne remplace pas
        }
    })
    .into_owned()
}

pub fn expand_arg(commandline: String) -> Result<String, anyhow::Error> {
    let path: PathBuf = std::env::current_exe()?; // <-- `PathBuf` stocké ici
    let binfile = path
        .to_str()
        .ok_or(anyhow::anyhow!("Chemin invalide UTF-8"))?;
    let path_parent = path
        .parent()
        .ok_or(anyhow::anyhow!("Chemin invalide UTF-8"))?;
    let binpath = path_parent
        .to_str()
        .ok_or(anyhow::anyhow!("Chemin invalide UTF-8"))?;
    let replaced = commandline
        .replace("${BINFILE}", &binfile)
        .replace("${BINPATH}", &binpath);
    let replaced = replace_patterns(replaced);

    let expanded: std::borrow::Cow<'_, str> = shellexpand::env(&replaced)?; // Expands %APPDATA% or any other environment variable
    debug!("expand args: {}", expanded);
    Ok(expanded.to_string())
}
