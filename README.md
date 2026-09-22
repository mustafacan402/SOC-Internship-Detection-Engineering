# 🛡️ SOC Detection Engineering & Threat Hunting Lab

## 📖 Overview
This repository contains the documentation, attack simulations, and custom correlation rules developed during my Security Operations Center (SOC) internship at KoçSistem. 

The project demonstrates a full-cycle detection engineering process: from building an isolated Active Directory environment to executing advanced adversary emulations and optimizing SIEM (IBM QRadar) detection capabilities. The simulations are strictly mapped to the **MITRE ATT&CK** framework.

## 🏗️ Architecture & Tech Stack

*   **SIEM Platform:** IBM QRadar
*   **Attacker Machine (Red Team):** Kali Linux
*   **Target Infrastructure (Active Directory):** Windows Server 2022 (Domain Controller & Auth Server)
*   **Network Security:** pfSense
*   **Log Collection & Telemetry:** Windows Event Forwarding (WEF), WinCollect, Sysmon
*   **Simulation & Attack Tools:** Atomic Red Team, Impacket, NetExec (nxc), Hydra, Nmap

### Network Topology
<img width="1169" height="547" alt="image" src="https://github.com/user-attachments/assets/3fd9e060-72da-42c5-ae93-2d63abcb7d11" />

---

## 🎯 Simulated Attack Scenarios (MITRE ATT&CK)

During the lab, various TTPs were executed, analyzed at the payload level, and custom detection rules were created.

| Tactic | Technique ID | Technique Name | Tool/Method |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078.002 | Valid Accounts | Remote Desktop Protocol (RDP) |
| **Execution** | T1053.005 | Scheduled Task/Job | Atomic Red Team |
| **Persistence** | T1547.001 | Registry Run Keys | `reg add` / Atomic Red Team |
| **Privilege Escalation**| T1543.003 | Windows Service | `sc create` |
| **Defense Evasion** | T1686.003 | Disable System Firewall| `netsh advfirewall` |
| **Credential Access** | T1110.001 | Password Guessing | Hydra (RDP Brute Force) |
| **Lateral Movement** | T1021.002 | SMB/Windows Admin Shares| Impacket-psexec / NetExec |
| **Command and Control**| T1071.001 | Web Protocols | Custom HTTP Beaconing |
| **Exfiltration** | T1048.003 | Unencrypted Non-C2 Protocol| Raw TCP Socket / Netcat |
| **Impact** | T1490 | Inhibit System Recovery| `vssadmin delete shadows` |

---
