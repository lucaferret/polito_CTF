#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_aslr', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    else:
        return process(elf.path)

p = conn()

p.interactive()
