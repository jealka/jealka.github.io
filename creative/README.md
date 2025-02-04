# Write-Up: Creative
**Date:** 02/04/2025 \
**User:** [JAKK](https://tryhackme.com/p/JAKK)

[Creative](https://tryhackme.com/r/room/creative) is an easy-ranked CTF box, testing us on exploiting a vulnerable web application, gaining an initial foothold on the webserver and elevate our privileges to root by exploiting a dangerous misconfiguration.

## Reconaissance
### Port Scan
To gain a foothold on the victim's system, we need to determine how we can interact with it, i.e. finding out about open ports and services being offered. We can conduct the port scan with `nmap`, splitting the port discovery and service identification in two. This gives us the advantage that we can check all 65,536 ports without having to conduct the costly service discovery (`-sV`) and default scripts scans (`-sC`) on all of these. Be aware that the flag `-T4` gives us an advantage in performance but makes us detectable for firewalls and other security tools.

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

We can see that port `22` and `80` are open, probably offering SSH and a webserver respectively. To ensure this assumption, we conduct a service discovery and default script scans on those two ports.

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
