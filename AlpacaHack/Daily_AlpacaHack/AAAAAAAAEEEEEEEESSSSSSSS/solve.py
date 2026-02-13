#!/usr/bin/env python3
from pwn import *
import json
import base64
from Crypto.Util.number import *
from Crypto.Cipher import AES 

HOST = args.HOST or 'localhost'
PORT = int(args.PORT or 1337)

# context.log_level = 'debug'

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(['python3', 'server.py'])

def recv_hex(io):
    return bytes.fromhex(io.recvline().strip().decode())

def send_hex(io, b):
    io.sendline(b.hex().encode())

def attack(io):
    flag_charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_"
    flag = b''
    ct_dict = {}

    io.recvuntil(b'ciphertext(hex): ')
    ciphertext = recv_hex(io)
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    for c1 in flag_charset:
        for c2 in flag_charset:
            c = bytes([c1])*8 + bytes([c2])*8
            io.recvuntil(b'encrypt (hex): ')
            send_hex(io, c)
            io.recvuntil(b'ciphertext(hex): ')
            ct = recv_hex(io)
            
            ct_dict[ct] = bytes([c[0]]) + bytes([c[8]])
    
    for block in blocks:
        flag += ct_dict[block]

    print(flag)

def main():
    io = start()
    attack(io)
    io.interactive()

if __name__ == '__main__':
    main()
