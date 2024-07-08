###############
Networked
Linux box vulnerable to file upload bypass, leading to code execution. 
Due to improper sanitization, a crontab running as the user can be exploited 
to achieve command execution
###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.85.185 -v
        PORT    STATE  SERVICE VERSION
        22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
        | ssh-hostkey: 
        |   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
        |   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
        |_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
        80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
        |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
        443/tcp closed https

        # Port 80:
        Apache 2.4.6
        PHP 5.4.16

        nikto -h http://10.129.85.185:80/ 
        └─$ gobuster dir -u http://10.129.85.185/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
        /uploads              (Status: 301) [Size: 237] [--> http://10.129.85.185/uploads/]
        /backup               (Status: 301) [Size: 236] [--> http://10.129.85.185/backup/]

        # We found backup.tar
        http://10.129.85.185/backup/

        # We found:
            http://10.129.85.185/photos.php
            http://10.129.85.185/upload.php

        # from the code on upload.php:
            $validext = array('.jpg', '.png', '.gif', '.jpeg');