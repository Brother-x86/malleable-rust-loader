use log::debug;
use rand::Rng;
use regex::Regex;
use std::path::Path;
use std::path::PathBuf;
use std::env;
use anyhow::{anyhow, Context, Result};
use walkdir::WalkDir;

use cryptify::encrypt_string;

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

// CHATGPT code replacement 03-08-2026


// -----------------------------------------------------------------------------
// Regex builders
// -----------------------------------------------------------------------------

fn random_placeholder_regex() -> Regex {
    Regex::new(r"\$\{(RANDOMHEX|RANDOMINT):(\d+)\}").unwrap()
}

fn env_placeholder_regex() -> Regex {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap()
}

// -----------------------------------------------------------------------------
// Expansions
// -----------------------------------------------------------------------------

/// Remplace uniquement:
/// - ${BINFILE}
/// - ${BINPATH}
/// - ${ENVVAR}
///
/// Ne touche PAS à:
/// - ${RANDOMHEX:8}
/// - ${RANDOMINT:2}
pub fn expand_arg_no_random(input: &str) -> Result<String> {
    let exe_path = env::current_exe()?;
    let binfile = exe_path
        .to_str()
        .ok_or_else(|| anyhow!(format!("{}",encrypt_string!("Chemin invalide UTF-8"))))?;

    let exe_parent = exe_path
        .parent()
        .ok_or_else(|| anyhow!(format!("{}",encrypt_string!("Impossible récup le parent"))))?;

    let binpath = exe_parent
        .to_str()
        .ok_or_else(|| anyhow!(format!("{}",encrypt_string!("Chemin invalide UTF-8 pour le parent"))))?;

    /* 
    let replaced = input
        .replace("${BINFILE}", binfile)
        .replace("${BINPATH}", binpath);
    */
    let replaced = input
        .replace(&format!("{}",encrypt_string!("${BINFILE}")), binfile)
        .replace(&format!("{}",encrypt_string!("${BINPATH}")), binpath);

    let env_re = env_placeholder_regex();

    let expanded = env_re.replace_all(&replaced, |caps: &regex::Captures| {
        let key = &caps[1];

        match key {
            // déjà traités au-dessus
            "BINFILE" => binfile.to_string(),
            "BINPATH" => binpath.to_string(),

            // IMPORTANT:
            // ici on ne touche pas aux mots-clés random
            "RANDOMHEX" | "RANDOMINT" => caps[0].to_string(),

            // variable d'environnement classique
            _ => env::var(key).unwrap_or_else(|_| caps[0].to_string()),
        }
    });

    Ok(expanded.into_owned())
}

/// Remplace les patterns random:
/// - ${RANDOMHEX:8}
/// - ${RANDOMINT:2}
fn replace_patterns(input: &str) -> String {
    let re = random_placeholder_regex();

    re.replace_all(input, |caps: &regex::Captures| {
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

/// Expansion complète:
/// 1. variables statiques / env
/// 2. random
pub fn expand_arg(input: &str) -> Result<String> {
    let expanded = expand_arg_no_random(input)?;
    let final_value = replace_patterns(&expanded);
    debug!("expand args: {}", final_value);
    Ok(final_value)
}

// -----------------------------------------------------------------------------
// Forward path
// -----------------------------------------------------------------------------

pub fn calculate_path(path_with_env: &str) -> Result<PathBuf> {
    let expanded = expand_arg(path_with_env)?;
    Ok(PathBuf::from(expanded))
}

// -----------------------------------------------------------------------------
// Reverse path
// -----------------------------------------------------------------------------

fn contains_random_placeholder(s: &str) -> bool {
    random_placeholder_regex().is_match(s)
}

fn build_reverse_regex(pattern: &str) -> Result<Regex> {
    let re = random_placeholder_regex();

    let mut out = String::from("(?i)^");
    let mut last = 0;

    for caps in re.captures_iter(pattern) {
        let m = caps.get(0).context(format!("{}",encrypt_string!("capture regex invalide")))?;
        out.push_str(&regex::escape(&pattern[last..m.start()]));

        let kind = &caps[1];
        let len: usize = caps[2]
            .parse()
            .with_context(|| format!("Longueur invalide dans {}", &caps[0]))?;

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

/// Prend le plus profond préfixe fixe avant le premier composant contenant un RANDOM*
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

/// Retourne tous les chemins du filesystem correspondant au pattern
pub fn calculate_path_reverse(path_with_env: &str) -> Result<Vec<PathBuf>> {
    let expanded_pattern = expand_arg_no_random(path_with_env)?;

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
        let candidate = entry.path().to_string_lossy();

        if re.is_match(&candidate) {
            matches.push(entry.path().to_path_buf());
        }
    }

    Ok(matches)
}