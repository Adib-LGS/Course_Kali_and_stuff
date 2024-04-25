****
Red Team Capstone Challenge
****

 

SSH Username
e-citizen

SSH Password
stabilitythroughcurrency

SSH IP
10.200.116.250

add:  http://swift.bank.thereserve.loc/ in etc/hosts with Web Server IP

 

1-Enumeration:

    =======================================
    Thank you for registering on e-Citizen for the Red Team engagement against TheReserve.

    Please take note of the following details and please make sure to save them, as they will not be displayed again.
    =======================================

    Username: pitchblack
    Password: y__vMnjBuo_DhNrR
    MailAddr: pitchblack@corp.th3reserve.loc
    IP Range: 10.200.116.0/24

  

 

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


        OCTOBER CMS Vulns:  <------------!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
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


            Possible Attack Path (We have employees Names):
                -User Enum or Brute Force

                -Phishing:
                    http://swift.bank.thereserve.loc/october/index.php/demo/contactus:
                        Once you are ready, send us your CV and last three months banking statements

                        applications@corp.thereserve.loc
            
                        -Macro phshing - remote shell ?


    VPN:
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

                We add the VPN IP Machine to the ovpn file

                sudo openvpn corpUsername.ovpn

            WE GET ACCESS TO THE INTERNAL NETWORK !!!!!
