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


            We try to login with guest:guest after redirection we found the HomePage:
                http://10.129.96.159:8080/HomePage.do

                https://www.exploit-db.com/exploits/46674

            We test a request:
                http://10.129.96.159:8080/mc/WorkOrder.do?woID=11&mode=viewWO&more=details&isOverDue=false

            We found a creation form:
                http://10.129.96.159:8080/WorkOrder.do?reqTemplate=61



        Port 445:

            └──╼ [★]$ enum4linux -u "guest" -p "" 10.129.96.159

            ──╼ [★]$ cme smb 10.129.96.159 -u " -p" : NULL SESSION:
                SMB         10.129.96.159   445    HELPLINE         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HELPLINE) (domain:HELPLINE) (signing:False) (SMBv1:False)


            cme smb 10.129.96.159 -u'a' -p

            └──╼ [★]$ smbclient -U '' -L//10.129.96.159
                Password for [WORKGROUP\]:
                session setup failed: NT_STATUS_LOGON_FAILURE


