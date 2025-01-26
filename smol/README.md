# Write-up: **Smol**
Smol is a medium-ranked CTF box that introduces us to vulnerable Wordpress plugins, highlighting the need for website owners to keep dependencies up-to-date and to consider the source and reputation of installed plugins. The vulnerable web front-end then allows the execution of code on the web server, allowing to obtian a foothold on the system. Ultimately, root access is obtained through a combination of poorly managed passwords and misconfigurations.

## Reconaissance
The first step is to scan the host for open ports and find out about services that are offered. With `nmap`, we scan the 1000 most popular ports.
```
nmap -sV smol.thm
```
As the result shows us, two ports are open, offering the service SSH and a webpage.
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

When we try to visit the website, we get redirected to `www.smol.thm`, which is unknown to our domain server. Subsequently, we add the domain to our `/etc/hosts` file, allowing us to open the page.
