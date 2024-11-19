use crate::link::Link;
use crate::link::LinkFetch;
use log::debug;
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use cryptify::encrypt_string;

use anyhow::bail;
use std::thread;

use rand::seq::SliceRandom;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Advanced {
    pub random: u64, // fetch only x random link from pool and ignore the other, (0 not set)
    pub max_link_broken: u64, // how many accepted link broken before switch to next pool if no conf found, (0 not set)
    pub parallel: bool,       // try to fetch every link in the same time, if not its one by one
    pub linear: bool,         // fetch link in the order or randomized
    pub stop_same: bool,      // stop if found the same conf -> not for parallel_fetch
    pub stop_new: bool,       // stop if found a new conf -> not for parallel_fetch
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PoolMode {
    SIMPLE,
    ADVANCED(Advanced),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PoolLinks {
    pub pool_links: Vec<Link>,
    pub pool_mode: PoolMode,
}

impl PoolLinks {
    pub fn update_pool(&self, config: &Config) -> Result<Config, anyhow::Error> {
        match &self.pool_mode {
            PoolMode::SIMPLE => self.update_links_simple(config),
            PoolMode::ADVANCED(advanced) => self.update_links_advanced(config, advanced),
        }
    }

    //TODO update with date check and remove DECISION message, only print the config number if needed.
    pub fn update_links_simple(&self, config: &Config) -> Result<Config, anyhow::Error> {
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
            if config.date <= newconf.date {
                info! {"{}",encrypt_string!("config date : OK")};
                return Ok(newconf);
            } else {
                info! {"{}",encrypt_string!("config date : TOO OLD")};
            }
        }
        bail!("{}", encrypt_string!("No VALID fresh new config found in Pool"))
    }

    /*
        pub struct Advanced {
        pub random:u64,             // fetch only x random link from pool and ignore the other, (0 not set)
        pub max_link_broken:u64,    // how many accepted link broken before switch to next pool if no conf found, (0 not set)
        pub parallel:bool,          // try to fetch every link in the same time, if not its one by one
        pub linear:bool,            // fetch link in the order or randomized
        pub stop_same:bool,         // stop if found the same conf -> not for parallel_fetch
        pub stop_new:bool,          // stop if found a new conf -> not for parallel_fetch
    }
     */

    pub fn update_links_advanced(
        &self,
        config: &Config,
        advanced: &Advanced,
    ) -> Result<Config, anyhow::Error> {
        let mut fetch_configs: Vec<(Config, i32)> = vec![];
        //let pool_link: Vec<&Link>;
        let pool_link: Vec<Link>;

        if advanced.random != 0 {
            // TODO add advanced.random and remove 3 and test if advance.random < size -> not tested
            //let sample: Vec<_> = self.pool_links
            info!(
                "{}{}/{}",
                encrypt_string!("[+] randomly choose only "),
                advanced.random,
                self.pool_links.len()
            );
            let sample: Vec<Link> = self
                .pool_links
                .choose_multiple(
                    &mut rand::thread_rng(),
                    advanced
                        .random
                        .try_into()
                        .expect("Value too large to fit into usize"),
                )
                .cloned()
                .collect();
            pool_link = sample;
            //pool_link  // TODO random
        } else if advanced.linear {
            pool_link = self.pool_links.clone();
        } else {
            todo!()
            //pool_link=todo!() // TODO not linear -> randomized order, on devrait ptet renommer comme ça.
        }

        let pool_link_len: usize = pool_link.len();

        //TODO: only needed if parallel.
        let mut handle_list: Vec<thread::JoinHandle<Result<(Config, i32), anyhow::Error>>> = vec![];
        let mut link_nb: i32 = 0;

        if advanced.parallel {
            info!("[+] fetch all link in parallel")
        } else {
            info!("[+] fetch all link one by one")
        }

        for link in pool_link {
            link_nb = link_nb + 1;
            info!(
                "{}/{}{}{:?}",
                link_nb,
                &pool_link_len,
                encrypt_string!(" Link: "),
                &link.get_target()
            );

            if advanced.parallel {
                let thread_link = link.clone();
                let thread_config = config.clone();
                let handle: thread::JoinHandle<Result<(Config, i32), anyhow::Error>> =
                    thread::spawn(move || {
                        debug!("thread begin, link: {}", link_nb);
                        //TODO pas de unwrap ici, faire un jolie message de crash
                        let newconfig: Config = thread_link.fetch_config(&thread_config)?;
                        debug!("thread end, link: {}", link_nb);
                        Ok((newconfig, link_nb))
                    });
                handle_list.push(handle);
            } else {
                // TODO deal with stop_same and stop_new (avec des return)
                todo!()
            }
        }

        if advanced.parallel {
            info!("[+] all thread run to fetch a config, wait them finish to join");

            for handle in handle_list {
                match handle.join() {
                    Ok(Ok(conf_i)) => fetch_configs.push(conf_i),
                    Ok(Err(error)) => warn!(
                        "{}{:?}",
                        encrypt_string!("Thread link fail to fetch: "),
                        error
                    ),
                    Err(error) => warn!(
                        "{}{:?}",
                        encrypt_string!("Thread link fail to fetch: "),
                        error
                    ),
                };
            }
            info!(
                "[+] all thread finish, {}/{} succeed",
                fetch_configs.len(),
                pool_link_len
            );
        }

        //TODO max_link_broken -> en fonction de la taille de config_list, ca donne combien de lien broken ?  , pour ca il faudrait checker pool_link_len
        self.choose_config_from_config_list(config, advanced, fetch_configs)
    }

    pub fn choose_config_from_config_list(
        &self,
        config: &Config,
        _advanced: &Advanced,
        config_list: Vec<(Config, i32)>,
    ) -> Result<Config, anyhow::Error> {
        if config_list.len() == 0 {
            bail!(
                "{}",
                encrypt_string!("No VALID config found in Pool: empty list")
            )
        }
        // place the first config as choosen config
        let mut config_choosen: Config = config_list[0].0.clone();
        let mut nb_choosen: i32 = config_list[0].1.clone();
        info!("First choosen config set to {}", nb_choosen);

        // if more config, compare date to choosen one
        if config_list.len() >= 2 {
            for (newconf, i) in config_list[1..].to_vec() {
                if config_choosen.date <= newconf.date {
                    if newconf.is_same_loader(&config_choosen) {
                        info! {"{}{}",encrypt_string!("config date : OK, same config of the choosen, link: "),i};
                    } else {
                        config_choosen = newconf;
                        nb_choosen = i;
                        info! {"{}{}",encrypt_string!("config date : OK, NEW choosen config, link: "),nb_choosen};
                    }
                } else {
                    info! {"{}{}",encrypt_string!("config date : TOO OLD, link: "),i};
                }
            }
        }
        if config.date <= config_choosen.date {
            info!(
                "{}{}",
                encrypt_string!("[+] choose CONFIG fetch from link: "),
                nb_choosen
            );
            Ok(config_choosen)
        } else {
            info!(
                "{}{}",
                encrypt_string!("[+] all conf are older than actual config: "),
                config.date
            );
            bail!(
                "{}",
                encrypt_string!(
                    "No VALID config found in Pool: actual running config.date is superior to all config"
                )
            )
        }
    }
}

//use std::time::Duration;
