# Write-Up: Creative
**Date:** 02/04/2025 \
**User:** [JAKK](https://tryhackme.com/p/JAKK)

[Creative](https://tryhackme.com/r/room/creative) is an easy-ranked CTF box, challenging us to exploit a vulnerable web application, which opens us the possibility to compromise the web server and elevate our privileges with the aid of a dangerous misconfiguration.


## Reconaissance
### Port Scan
To gain a foothold on the victim's system, we first need to determine how we can interact with it, i.e. finding out about open ports and services being offered. We conduct a port scan with `nmap`, splitting port discovery and service identification in two. This gives us the advantage that we can check all 65,536 ports being open without conducting the costly service discovery (`-sV`) and default scripts scans (`-sC`) at the same time. The open ports found are then specifically scanned for services. Be aware that the flag `-T4` gives us an advantage in performance but makes the scan easily detectable for firewalls and other security measures.

```
> nmap -T4 -p0-65535 creative.thm
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-04 04:49 CST
Nmap scan report for creative.thm (10.10.109.142)
Host is up (0.047s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 121.44 seconds
```

We see that port `22` and `80` are open, presumely offering SSH and a web server respectively. To ensure this assumption, we conduct a service discovery and default script scan for those two ports, which confirms the hypothesis.

```
> nmap -T4 -p22,80 -sV -sC creative.thm
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-04 05:02 CST
Nmap scan report for creative.thm (10.10.109.142)
Host is up (0.032s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
|_  256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Creative Studio | Free Bootstrap 4.3.x template
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.91 seconds
```

### Discovering the Web Service
The website offered on port `80` is an almost unaltered web template, only referencing a few images and the `/components.html` resource. All in all, neither homepage nor `/components.html` contain any relevant parts that could help us in compromising the machine. But maybe there are other hidden resources, which we will try to enumerate with `gobuster`.

```
> gobuster dir -u http://creative.thm -w /usr/share/wordlists/dirb/common.txt
/assets               (Status: 301) [Size: 178] [--> http://creative.thm/assets/]
/index.html           (Status: 200) [Size: 37589]
```

```
> gobuster dir -u http://creative.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt,bak,sql,db,bac
/index.html           (Status: 200) [Size: 37589]
/assets               (Status: 301) [Size: 178] [--> http://creative.thm/assets/]
/components.html      (Status: 200) [Size: 41148]
```

Unfortunately, the enumeration of URIs doesn't bring us anywhere.

We could check if there are any subdomains that exist. To do this, we need to know the domain name of the web server, which is not indicated anywhere on the pages we have seen. But maybe we'll be lucky if we use the name of the room, i.e. `creative.thm`. To enumerate subdomains, we use the `vhost` option of `gobuster` and a wordlist of popular subdomain names that [can be found on Github](https://github.com/rbsec/dnscan/blob/master/subdomains-10000.txt).

```
> gobuster vhost --append-domain --domain creative.thm --url http://10.10.109.142 --wordlist ~/Downloads/subdomains-10000.txt
Found: beta.creative.thm Status: 200 [Size: 591]
```

Great, we found another segment of the website under the subdomain `beta`! Let's add `beta.creative.thm` to our `/etc/hosts` file and inspect the site we just found.
