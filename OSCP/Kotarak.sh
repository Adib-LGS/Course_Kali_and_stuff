#Kotarak
#

1-Enumeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.1.117 -v
        give us few results lets us "-p-" flag

        PORT      STATE SERVICE VERSION
        22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   2048 e2:d7:ca:0e:b7:cb:0a:51:f7:2e:75:ea:02:24:17:74 (RSA)
        |   256 e8:f1:c0:d3:7d:9b:43:73:ad:37:3b:cb:e1:64:8e:e9 (ECDSA)
        |_  256 6d:e9:26:ad:86:02:2d:68:e1:eb:ad:66:a0:60:17:b8 (ED25519)
        8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
        | ajp-methods: 
        |   Supported methods: GET HEAD POST PUT DELETE OPTIONS
        |   Potentially risky methods: PUT DELETE
        |_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
        8080/tcp  open  http    Apache Tomcat 8.5.5
        |_http-favicon: Apache Tomcat
        |_http-title: Apache Tomcat/8.5.5 - Error report
        | http-methods: 
        |   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
        |_  Potentially risky methods: PUT DELETE
        60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
        |_http-title:         Kotarak Web Hosting        
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_http-server-header: Apache/2.4.18 (Ubuntu)
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
