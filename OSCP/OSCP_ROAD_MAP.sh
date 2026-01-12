```markdown
# 🧠 Hack The Box – OSCP Preparation Roadmap

> Curated list of Hack The Box machines extracted from the provided screenshot,  
> categorized and enriched with **skills**, **attack focus**, and **OSCP relevance**.

---

## 📌 Table of Contents

- [Linux Boxes](#-linux-boxes)
- [Windows Boxes](#-windows-boxes)
- [Windows Active Directory Boxes](#-windows-active-directory-boxes)
- [Post‑OSCP / Challenge Section](#-post-oscp--challenge-section)
- [Recommended OSCP Progression Path](#-recommended-oscp-progression-path)
- [Notes & Tips](#-notes--tips)

---

## 🟨 Linux Boxes

| Machine | Main Skills | OSCP Relevance |
|------|------------|---------------|
| Busqueda | Web fuzzing, OSINT | ⭐⭐⭐ |
| UpDown | Web exploitation, sudo abuse | ⭐⭐⭐⭐ |
| Sau | CVE exploitation, privesc | ⭐⭐⭐ |
| Help | File upload, LFI/RCE | ⭐⭐⭐ |
| Broker | Web logic flaws | ⭐⭐⭐ |
| Intentions | Auth bypass, web chaining | ⭐⭐⭐⭐ |
| Soccer | API abuse, SSRF | ⭐⭐⭐⭐ |
| Keeper | Credential reuse, privesc | ⭐⭐⭐ |
| Monitored | Monitoring misconfig | ⭐⭐⭐ |
| BoardLight | Web app privesc | ⭐⭐⭐ |
| Networked | NFS, misconfig | ⭐⭐⭐⭐ |
| CozyHosting | Spring Boot, RCE | ⭐⭐⭐⭐ |
| Editorial | Web enumeration | ⭐⭐⭐ |
| Magic | SQLi, file upload | ⭐⭐⭐⭐ |
| Pandora | SNMP abuse, privesc | ⭐⭐⭐⭐ |
| Builder | CI/CD abuse | ⭐⭐⭐ |
| LinkVortex | Web routing abuse | ⭐⭐⭐ |
| Dog | Custom service | ⭐⭐⭐ |
| Usage | Misuse of binaries | ⭐⭐⭐ |

---

## 🟦 Windows Boxes

| Machine | Main Skills | OSCP Relevance |
|------|------------|---------------|
| Escape | SMB, creds reuse | ⭐⭐⭐ |
| Servmon | Services abuse | ⭐⭐⭐ |
| Support | AD exposure | ⭐⭐⭐ |
| StreamIO | SQL, file disclosure | ⭐⭐⭐⭐ |
| Blackfield | SMB, AD abuse | ⭐⭐⭐⭐ |
| Intelligence | Metadata, NTLM relay | ⭐⭐⭐⭐ |
| Jeeves | Jenkins, token abuse | ⭐⭐⭐ |
| Manager | GPP, creds | ⭐⭐⭐ |
| Access | SMB enumeration | ⭐⭐⭐ |
| Aero | Web + Windows privesc | ⭐⭐⭐ |
| Mailing | SMTP abuse | ⭐⭐⭐ |
| Administrator | Admin abuse | ⭐⭐⭐ |
| Certified | Cert abuse intro | ⭐⭐⭐⭐ |

---

## 🟩 Windows Active Directory Boxes

| Machine | Focus Area | Key Techniques |
|------|-----------|----------------|
| Active | AD basics | SMB, Kerberos |
| Forest | AD fundamentals | Kerberoasting |
| Sauna | AD creds | AS‑REP roast |
| Monteverde | LDAP abuse | Password spray |
| Timelapse | Certificates | ADCS |
| Return | Printer bug | NTLM relay |
| Cascade | ACL abuse | BloodHound |
| Flight | AD delegation | RBCD |
| Blackfield | Advanced AD | DCSync |
| Cicada | Lateral movement | WinRM |
| Escape | Hybrid AD | SMB + AD |
| Adagio | Enterprise AD | Full chain |
| TheFrizz | Complex AD | Multi‑pivot |

---

## 🟥 Post‑OSCP / Challenge Section

| Machine | OS | Focus |
|------|----|-------|
| Mentor | Linux | Pivoting |
| Absolute | Windows | Hard AD |
| Outdated | Windows | Legacy exploitation |
| Atom | Windows | Modern AD |
| APT | Windows | Red Team realism |
| Aero | Windows | Multi‑stage |
| Cerberus | Hybrid | Cross‑OS |
| Multimaster | Windows | Multi‑domain |
| Cereal | Linux | Web chaining |
| Quick | Linux | Reverse proxy |
| Authority | Windows | Domain takeover |
| Clicker | Linux | Logic abuse |
| Rebound | Windows | Blue/Red mix |
| Mailing | Windows | Mail infra |

---

## 🎯 Recommended OSCP Progression Path

### Phase 1 – Foundations
```

Active → Forest → Sauna → Networked → Pandora → Magic

```

### Phase 2 – Intermediate
```

Monteverde → Cascade → Soccer → StreamIO → Blackfield

```

### Phase 3 – Advanced OSCP‑like
```

Timelapse → Return → Flight → Intelligence → Certified

```

### Phase 4 – Post‑OSCP / Realism
```

APT → Multimaster → Authority → Cerberus

```

---

## 🧠 Notes & Tips

- 🔑 Always extract **credentials** early (configs, LDAP, SMB, SQL)
- 🩸 Use **BloodHound** on every AD box
- 📜 Take **structured notes** (Enumeration → Exploit → Privesc)
- ⏱ Practice **time‑boxed enumeration** (OSCP constraint)
- ❌ Avoid Metasploit except where allowed

---

> ✅ This roadmap is designed to simulate **real OSCP exam conditions**  
> while progressively building confidence and attack intuition.

```

---
