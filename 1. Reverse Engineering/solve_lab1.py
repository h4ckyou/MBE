#!/usr/bin/python3

username = "A"*31
serial = (ord(username[3]) ^ 0x1337) + 0x5EEDED
n = len(username)

for i in range(n):
    serial += (serial ^ ord(username[i])) % 0x539

print(f"Username: {username}")
print(f"Generated serial: {serial}")
