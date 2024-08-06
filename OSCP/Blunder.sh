###############
Blunder
machine that features a Bludit CMS instance running on port 80. 
The website contains various facts about different genres. 
###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.95.225 -v
        PORT   STATE  SERVICE VERSION
        21/tcp closed ftp
        80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
        |_http-title: Blunder | A blunder of interesting facts
        |_http-favicon: Unknown favicon MD5: A0F0E5D852F0E3783AF700B6EE9D00DA
        |_http-server-header: Apache/2.4.41 (Ubuntu)
        |_http-generator: Blunder
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS


    # Port 80:
        Apache 2.4.41
        http://10.129.95.225/admin/

        └─$ nikto -h http://10.129.95.225:80/ 
            http://10.129.95.225/install.php

        BLUDIT 3.9.2 - Login page:
            We found the version in the HEADER - favicon.png
            http://10.129.95.225/admin/site

        We found anti brute force exploit:
            https://rastating.github.io/bludit-brute-force-mitigation-bypass/
            python brute force script
            https://github.com/musyoka101/Bludit-CMS-Version-3.9.2-Brute-Force-Protection-Bypass-script/blob/master/bruteforce.py

        We found Creds:
        fergus:RolandDeschain
