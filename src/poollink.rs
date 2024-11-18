//use indexmap::IndexMap;
use crate::link::Link;
//use log::debug;
//use log::info;
//use log::warn;
use serde::{Deserialize, Serialize};
//use std::collections::BTreeMap;

use crate::config::Config;
use cryptify::encrypt_string;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PoolMode {
    MODE1,
    MODE2,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PoolLinks {
    pub pool_links: Vec<Link> ,
    pub pool_mode: PoolMode,
}

impl PoolLinks {
    pub fn update_pool(&self, config: &Config) -> Config {
    
        // TODO remplace ça !
        // et on pourait renvoyer un booléen pour PAS updater la conf, si on a pas la flemme.
        let newconf=config.clone();
        newconf
        //todo!()
    }


}
