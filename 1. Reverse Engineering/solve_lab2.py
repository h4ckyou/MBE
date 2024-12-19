#!/usr/bin/python3

def xor(s, key):
    r = b""
    for i in s:
        r += bytes([ord(i) ^ key])
    
    return r

s = "Q}|u`sfg~sf{}|a3"
known = ord("C")
key = xor(s, known)[0]

password = 0x1337D00D - key
print(f"Password: {password}")
