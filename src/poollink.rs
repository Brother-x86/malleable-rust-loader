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
    pub accept_old: bool, // accept conf older than the active one -> true not recommended, need to fight against hypothetic valid config replay.
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PoolMode {
    SIMPLE,
    ADVANCED(Advanced),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct PoolLinks {
    pub pool_mode: PoolMode,
    pub pool_links: Vec<Link>,
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
        let advanced = Advanced {
            random: 0,          // fetch only x random link from pool and ignore the other, (0 not set)
            max_link_broken: 0, // how many accepted link broken before switch to next pool if no conf found, (0 not set)
            parallel: false,    // try to fetch every link in the same time, if not its one by one
            linear: true,       // fetch link in the order or randomized
            stop_same: true,    // stop if found the same conf -> not for parallel
            stop_new: true,     // stop if found a new conf -> not for parallel
            accept_old: false, // accept conf older than the active one -> true not recommended, need to fight against hypothetic valid config replay.
        };

        self.update_links_advanced(config, &advanced)
        // NOW call the

        /*
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
            //nex time its here //PLus besoin ///FIX
            if config.date <= newconf.date {
                info! {"{}",encrypt_string!("config date : OK")};
                return Ok(newconf);
            } else {
                info! {"{}",encrypt_string!("config date : TOO OLD")};
            }
        }
        bail!(
            "{}",
            encrypt_string!("No VALID fresh new config found in Pool")
        )
        */
    }

    pub fn update_links_advanced(
        &self,
        config: &Config,
        advanced: &Advanced,
    ) -> Result<Config, anyhow::Error> {
        let pool_link: Vec<Link>;

        // create pool_links
        if advanced.random != 0 {
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
        } else if advanced.linear {
            pool_link = self.pool_links.clone();
        } else {
            todo!()
            //pool_link=todo!() // TODO not linear -> randomized order, on devrait ptet renommer comme ça.
        }

        let pool_link_len: usize = pool_link.len();
        let mut link_nb: i32 = 0;

        // fetch pool_links and choose a VALID config
        if advanced.parallel {
            info!("[+] fetch all link in parallel");
            let mut handle_list: Vec<thread::JoinHandle<Result<(Config, i32), anyhow::Error>>> =
                vec![];
            let mut fetch_configs: Vec<(Config, i32)> = vec![];
            for link in pool_link {
                link_nb = link_nb + 1;
                info!(
                    "{}/{}{}{:?}",
                    link_nb,
                    &pool_link_len,
                    encrypt_string!(" Link: "),
                    &link.get_target()
                );
                //parallel
                let thread_link = link.clone();
                let thread_config = config.clone();
                let thread_advanced = advanced.clone();
                let handle: thread::JoinHandle<Result<(Config, i32), anyhow::Error>> =
                    thread::spawn(move || {
                        debug!("thread begin, link: {}", link_nb);
                        let newconfig: Config =
                            thread_link.fetch_config(&thread_config, &thread_advanced, link_nb)?;
                        debug!("thread end, link: {}", link_nb);
                        Ok((newconfig, link_nb))
                    });
                handle_list.push(handle);
                //not parallel
            }

            //only for parallel
            info!("[+] all thread run to fetch a config, wait them finish to join");

            for handle in handle_list {
                match handle.join() {
                    Ok(Ok(conf_i)) => fetch_configs.push(conf_i),
                    Ok(Err(error)) => warn!("{}{:?}", encrypt_string!("Thread failed: "), error),
                    Err(error) => warn!("{}{:?}", encrypt_string!("Thread failed: "), error),
                };
            }
            info!(
                "[+] all thread finish, {}/{} succeed",
                fetch_configs.len(),
                pool_link_len
            );
            //TODO max_link_broken -> en fonction de la taille de config_list, ca donne combien de lien broken ?  , pour ca il faudrait checker pool_link_len

            self.choose_config_from_config_list(config, advanced, fetch_configs)
        } else {
            info!("[+] fetch all link one by one");
            //TODO max_link_broken
            //TODO stop_same + stop_new -> avec une fetch_configs
            //let mut fetch_configs: Vec<(Config, i32)> = vec![];
            for link in pool_link {
                link_nb = link_nb + 1;
                info!(
                    "{}/{}{}{:?}",
                    link_nb,
                    &pool_link_len,
                    encrypt_string!(" Link: "),
                    &link.get_target()
                );
                let newconfig: Config = match link.fetch_config(config, advanced, link_nb) {
                    Ok(newconfig) => {
                        info!(
                            "{}{}",
                            encrypt_string!("[+] choose config of link "),
                            link_nb
                        );
                        newconfig
                    }
                    Err(error) => {
                        warn!("{}{:?}", encrypt_string!("Check failed: "), error);
                        continue;
                    }
                };
    
                return Ok(newconfig);
            }

            // TODO 3/5 info message same if some succeed.
            info!(
                "[+] check finish, 0/{} succeed",
                pool_link_len
            );

            bail!(
                "{}",
                encrypt_string!("No VALID config found in Pool: all link check")
            )
        }
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
        info!(
            "{}",
            encrypt_string!("[+] Begin to choose the config to return from pool")
        );

        let mut config_choosen: Config = config_list[0].0.clone();
        let mut nb_choosen: i32 = config_list[0].1.clone();
        debug!("initial choosen config, link: {}", nb_choosen);

        // if more config, compare date to choosen one
        if config_list.len() >= 2 {
            for (newconf, i) in config_list[1..].to_vec() {
                if config_choosen.date <= newconf.date {
                    if newconf.is_same_loader(&config_choosen) {
                        debug! {"{}{}",encrypt_string!("config date : OK, same config as choosen, link "),i};
                    } else {
                        config_choosen = newconf;
                        nb_choosen = i;
                        debug! {"{}{}",encrypt_string!("config date : OK, NEW choosen config, link "),nb_choosen};
                    }
                } else {
                    debug! {"{}{}",encrypt_string!("config date : TOO OLD, link "),i};
                }
            }
        }
        if config.date <= config_choosen.date {
            info!(
                "{}{}",
                encrypt_string!("[+] choose config of link "),
                nb_choosen
            );
            Ok(config_choosen)
        } else {
            info!(
                "{}{}",
                encrypt_string!("[+] all conf are older than actual config date: "),
                config.date
            );
            bail!(
                "{}{}",
                encrypt_string!(
                    "No VALID config found in Pool: actual running config.date is superior to all config: "
                ), config.date
            )
        }
    }
}
