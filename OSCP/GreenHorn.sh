#
#GreenHorn
#Pluck CMS 4.7.18
#GitHub Bad Practices
#
#


1-Enumeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.125.52 -v
        PORT     STATE SERVICE VERSION
        22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
        |_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
        80/tcp   open  http    nginx 1.18.0 (Ubuntu)
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_http-title: Did not follow redirect to http://greenhorn.htb/
        |_http-server-header: nginx/1.18.0 (Ubuntu)
        3000/tcp open  ppp?

        Port 80:
            nikto -h http://10.129.231.80:80 - pluck 4.7.18 

                http://greenhorn.htb/login.php:

                http://greenhorn.htb/README.md

                http://greenhorn.htb/install.php
                


        Port 3000:
            └──╼ [★]$ gobuster dir -u http://greenhorn.htb:3000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r
                /admin                (Status: 200) [Size: 11114]
                /issues               (Status: 200) [Size: 11112]
                /v2                   (Status: 401) [Size: 50]
                /explore              (Status: 200) [Size: 15992]
                /milestones           (Status: 200) [Size: 11112]
                /notifications        (Status: 200) [Size: 11112]


            http://greenhorn.htb:3000/user/login
            http://greenhorn.htb:3000/explore/repos


            └──╼ [★]$ searchsploit pluck 4.7.18
                -------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
                Exploit Title                                                                                                                                          |  Path
                -------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
                Pluck v4.7.18 - Remote Code Execution (RCE)                                                                                                             | php/webapps/51592.py


            └──╼ [★]$ locate php/webapps/51592.py
                /usr/share/exploitdb/exploits/php/webapps/51592.py

            

            http://greenhorn.htb:3000/explore/repos give us a reposity on git by a junior web dev:
                http://greenhorn.htb:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php

            We found encrypted Hash:
                d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163

            We past the hash in crack station:
                https://crackstation.net/
                    iloveyou1
                
                http://greenhorn.htb/login.php + iloveyou1





            
