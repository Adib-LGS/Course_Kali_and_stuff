###############
Bastard

###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.87.141 -v
        PORT      STATE SERVICE VERSION
        80/tcp    open  http    Microsoft IIS httpd 7.5
        |_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
        |_http-generator: Drupal 7 (http://drupal.org)
        |_http-server-header: Microsoft-IIS/7.5
        | http-methods: 
        |   Supported Methods: OPTIONS TRACE GET HEAD POST
        |_  Potentially risky methods: TRACE
        | http-robots.txt: 36 disallowed entries (15 shown)
        | /includes/ /misc/ /modules/ /profiles/ /scripts/ 
        | /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
        | /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
        |_/LICENSE.txt /MAINTAINERS.txt
        |_http-title: Welcome to Bastard | Bastard
        135/tcp   open  msrpc   Microsoft Windows RPC
        49154/tcp open  msrpc   Microsoft Windows RPC
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


    # Port 80:
        Drupal 7
        PHP 5.3.28
        http://10.129.87.141/rest/:
            "Services Endpoint "rest_endpoint" has been setup successfully."

    # Port 135:
        Try RPC connection:
            rpcclient -U "" -N 10.129.87.141
                rpcclient $> enumdomusers
                do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
                rpcclient $> enumdomgroups
                do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DEN