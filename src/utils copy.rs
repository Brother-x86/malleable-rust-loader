use log::debug;
use rand::Rng;
use regex::Regex;
use std::path::Path;
use std::path::PathBuf;

const DEFAULT_RANDOMHEX_LEN: usize = 8;
const DEFAULT_RANDOMINT_LEN: usize = 6;

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

use anyhow::{anyhow, Context, Result};
use walkdir::WalkDir;

fn replace_patterns(input: String) -> String {
    let re = Regex::new(r"\$\{(RANDOMHEX|RANDOMINT):(\d+)\}").unwrap();

    re.replace_all(&input, |caps: &regex::Captures| {
        let kind = &caps[1];
        let len: usize = caps[2].parse().unwrap_or(1);

        match kind {
            "RANDOMHEX" => generate_random_hex(len),
            "RANDOMINT" => generate_random_int(len),
            _ => caps[0].to_string(),
        }
    })
    .into_owned()
}

/// Remplace BINFILE / BINPATH / variables d'env, mais ne touche pas aux RANDOM*
pub fn expand_arg_no_random(commandline: &str) -> Result<String> {
    let exe_path = std::env::current_exe()?;
    let binfile = exe_path
        .to_str()
        .ok_or_else(|| anyhow!("Chemin invalide UTF-8 pour current_exe"))?;

    let exe_parent = exe_path
        .parent()
        .ok_or_else(|| anyhow!("Impossible de récupérer le parent de current_exe"))?;

    let binpath = exe_parent
        .to_str()
        .ok_or_else(|| anyhow!("Chemin invalide UTF-8 pour le parent de current_exe"))?;

    let replaced = commandline
        .replace("${BINFILE}", binfile)
        .replace("${BINPATH}", binpath);

    let protected = protect_random_placeholders(&replaced);

    let expanded = shellexpand::env(&protected)?;
    let restored = restore_random_placeholders(&expanded);

    Ok(restored)
}

pub fn expand_arg(commandline: &str) -> Result<String> {
    let expanded = expand_arg_no_random(commandline)?;
    let replaced = replace_patterns(expanded);
    debug!("expand args: {}", replaced);
    Ok(replaced)
}

pub fn calculate_path(path_with_env: &str) -> Result<PathBuf> {
    let expanded = expand_arg(path_with_env)?;
    Ok(PathBuf::from(expanded))
}

fn contains_random_placeholder(s: &str) -> bool {
    static PATTERN: &str = r"\$\{(?:RANDOMHEX|RANDOMINT)(?::\d+)?\}";
    Regex::new(PATTERN).unwrap().is_match(s)
}

fn build_reverse_regex(pattern: &str) -> Result<Regex> {
    let re = Regex::new(r"\$\{(RANDOMHEX|RANDOMINT)(?::(\d+))?\}")?;

    let mut out = String::from("(?i)^");
    let mut last = 0;

    for caps in re.captures_iter(pattern) {
        let m = caps.get(0).context("capture regex invalide")?;
        out.push_str(&regex::escape(&pattern[last..m.start()]));

        let kind = &caps[1];
        let len: usize = caps
            .get(2)
            .and_then(|m| m.as_str().parse::<usize>().ok())
            .unwrap_or_else(|| match kind {
                "RANDOMHEX" => DEFAULT_RANDOMHEX_LEN,
                "RANDOMINT" => DEFAULT_RANDOMINT_LEN,
                _ => 1,
            });

        match kind {
            "RANDOMHEX" => out.push_str(&format!(r"[A-Fa-f0-9]{{{}}}", len)),
            "RANDOMINT" => out.push_str(&format!(r"\d{{{}}}", len)),
            _ => out.push_str(&regex::escape(m.as_str())),
        }

        last = m.end();
    }

    out.push_str(&regex::escape(&pattern[last..]));
    out.push('$');

    Ok(Regex::new(&out)?)
}


/// Prend le plus profond préfixe fixe avant le premier composant contenant RANDOM*
fn find_search_root(pattern: &str) -> PathBuf {
    let path = Path::new(pattern);
    let mut root = PathBuf::new();
    let mut found_dynamic = false;

    for comp in path.components() {
        let comp_str = comp.as_os_str().to_string_lossy();

        if contains_random_placeholder(&comp_str) {
            found_dynamic = true;
            break;
        }

        root.push(comp.as_os_str());
    }

    if !found_dynamic {
        return path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
    }

    if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root
    }
}

/// Retourne tous les chemins du filesystem qui pourraient correspondre
/// à un pattern initialement passé à calculate_path()
pub fn calculate_path_reverse(path_with_env: &str) -> Result<Vec<PathBuf>> {
    let expanded_pattern: String = expand_arg_no_random(path_with_env)?;

    // S'il n'y a pas de RANDOM*, on retombe sur un comportement simple
    if !contains_random_placeholder(&expanded_pattern) {
        let concrete = PathBuf::from(expand_arg(path_with_env)?);
        return Ok(if concrete.exists() {
            vec![concrete]
        } else {
            Vec::new()
        });
    }

    let search_root = find_search_root(&expanded_pattern);
    if !search_root.exists() {
        return Ok(Vec::new());
    }

    let re = build_reverse_regex(&expanded_pattern)?;
    let mut matches = Vec::new();

    for entry in WalkDir::new(&search_root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let candidate = entry.path().to_string_lossy();
        if re.is_match(&candidate) {
            matches.push(entry.path().to_path_buf());
        }
    }

    Ok(matches)
}