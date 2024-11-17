//use indexmap::IndexMap;
use crate::link::Link;
use log::debug;
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::config::Config;
use cryptify::encrypt_string;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PoolMode {
    MODE1,
    MODE2,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PoolLinks {
    pub pool_links: BTreeMap<String, Vec<Link>>,
    pub mode: PoolMode,
}

impl PoolLinks {
    pub fn new() -> PoolLinks {
        PoolLinks {
            pool_links: BTreeMap::new(),
            mode: PoolMode::MODE1,
        }
    }
    pub fn update_config(&self, config: &Config) -> Config {
        let mut pool_nb = 0;
        for (pool_name , links ) in &self.pool_links{
            pool_nb = pool_nb + 1;
            info!(
                "{}/{}{}{:?}",
                pool_nb,
                &links.len(),
                encrypt_string!(" config link: "),
                &pool_name
            );

        }
    
        // TODO remplace ça !
        // et on pourait renvoyer un booléen pour PAS updater la conf, si on a pas la flemme.
        let newconf=config.clone();
        newconf
        //todo!()
    }


}
