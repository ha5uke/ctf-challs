import os
from Crypto.Cipher import AES

flag_charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}_"
flag = os.environ.get("FLAG", "Alpaca{________REDACTED________}").encode()
assert len(flag) == 32
assert all(c in flag_charset for c in flag)

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

ffffffffllllllllaaaaaaaagggggggg = b""

for c in flag:
    ffffffffllllllllaaaaaaaagggggggg += bytes([c] * 8)

ciphertext = cipher.encrypt(ffffffffllllllllaaaaaaaagggggggg)
print(f"ciphertext(hex): {ciphertext.hex()}")

while True:
    user_input = bytes.fromhex(input("plaintext to encrypt (hex): "))
    ciphertext = cipher.encrypt(user_input)
    print(f"ciphertext(hex): {ciphertext.hex()}")
