# OzCloths Cybersecurity Infrastructure Modernisation

OzCloths is a growing online clothing retailer that experienced increased cyber risk due to insecure legacy infrastructure, 
remote workforce expansion, and outdated security controls. 
This project redesigns OzCloths’s IT environment using **security-by-design, defense-in-depth**, and industry best practices, 
aligned with **NIST Cybersecurity Framework, NIST SP 800-53, and OWASP Top 10.**

> ## Risks in the Old Infrastructure
    The original OzCloths environment had several critical security flaws that 
    exposed the organisation to cyber attacks:

### Major Security Breaches & Risks
- SMB file sharing (Port 445) exposed directly to the internet
- No VPN for remote staff access
- No Multi-Factor Authentication (MFA)
- Weak password and access controls
- No IDS/IPS to detect or block attacks
- No firewall rules for threat filtering or DoS protection
- No malware or ransomware protection on servers
- Outdated software versions (WordPress, PHP, MySQL)
- No monitoring or alerting system
- Flat network with no segmentation
- No incident response or recovery plan

## These weaknesses made OzCloths vulnerable to:
- Brute-force attacks
- Ransomware infections
- Data breaches
- Credential theft
- SQL Injection and XSS attacks
- Distributed Denial of Service (DDoS)
- Insider threats
- Supply chain compromise

> ## **New Secure Infrastructure – Solution Overview**
The new infrastructure was redesigned with security-by-design and defense-in-depth principles. All remote access is now secure, monitored, and controlled, significantly reducing the attack surface.

## Key Security Objectives
- Secure remote access for employees
- Protect customer and business data
- Detect and block cyber attacks in real time
- Align with NIST CSF and OWASP Top 10
- Improve incident response and recovery
- Ensure business continuity and resilience

## **Security Improvements, Tools & Best Practices**

### Network & Firewall Security
- Tools: pfSense / UFW / Windows Firewall
- Removed all direct internet exposure (Port 445 closed)
- Strict inbound and outbound firewall rules
- DoS and brute-force traffic filtering
- Network segmentation for servers and users
- Logging and alerting enabled

### Secure Remote Access
- Tools: WireGuard
- Encrypted VPN tunnels for all remote staff
- No direct access to internal servers from the internet
- Access restricted based on user roles

### IDS / IPS (Intrusion Detection & Prevention)
- Tools: Snort
- Monitors network traffic in real time
- Detects brute-force, malware, SQL injection, XSS
- Automatically blocks malicious traffic
- Centralised alert logging and monitoring

### Web Server Hardening

- Tools: Apache hardening, Wordfence, Fail2Ban
- Removed server version banners
- Disabled directory listing
- Protected against OWASP Top 10 attacks
- Rate-limiting and brute-force protection

### Malware & Ransomware Protection

- Tools: ClamAV, Malwarebytes
- Real-time malware scanning
- Scheduled virus definition updates
- Regular system scans and alerts

### Multi-Factor Authentication (MFA)

- Tools: Duo Security

- #### MFA enforced for:
  - Windows Server login
  - VPN access
  - Administrative accounts
- Protects against stolen credentials

### Role-Based Access Control (RBAC)

- Tools: Active Directory
- Users assigned roles based on job function
- Least privilege principle enforced
- Admin access restricted and monitored
- Disabled unused and inactive accounts

> ## Practical approach - System Hardening and Imrove Security 

## Windows Server System Hardening (Active Directory)
### Objectives
- Protect user identities
- Prevent unauthorized access
- Secure authentication and access control
#### Hardening Steps
- Upgrade OS
    - Upgrade Windows Server 2012 → Windows Server 2022
- Patch Management
    - Enable automatic Windows Updates
- Account Policies
    - Password length ≥ 14 characters
    - Account lockout after 5 failed attempts
- Disable Legacy Protocols
    - Disable SMBv1
    - Disable NTLM where possible
- Secure RDP
    - Remove RDP port forwarding
    - Allow RDP only via VPN
- Audit & Logging
    - Logon auditing
    - Account changes
    - Privilege escalation
- Antivirus
    - Enable Microsoft Defender
    - Install Malwarebytes (real-time protection)

### Result: Secure authentication, reduced attack surface, and strong monitoring

## Linux Web Server Hardening (Ubuntu)

### Objectives
* Protect e-commerce website.
* Prevent **OWASP Top 10** attacks.

### Hardening Steps
* **OS Hardening**
    * Upgrade to Ubuntu 22.04 LTS.
    * Disable root SSH login.
* **Firewall (UFW)**
    * Allow 22 (SSH – VPN only).
    * Allow 80, 443 (Web).
* **Fail2Ban**
    * Protect: SSH, Apache, and WordPress login.
* **Apache Security**
    * Disable directory listing.
    * Hide server tokens.
* **PHP Hardening**
    * Disable `expose_php`.
    * Secure sessions.
* **WordPress Security**
    * Wordfence WAF.
    * Disable XML-RPC.
* **SSL/TLS**
    * HTTPS enforced.


### Result: Hardened web server protected from brute force, SQLi, and XSS.

---

## NAS Security Hardening (Synology)

### Objectives
* Protect sensitive business and customer data.

### Hardening Steps
* **Remove Port Forwarding:** Close SMB port 445 completely.
* **VPN-Only Access:** NAS accessible only via VPN.
* **Enable MFA:** Required for Admin and user accounts.
* **Access Control:** Implement least privilege permissions.
* **Encryption:** Encrypt sensitive shared folders.
* **Logging:** Enable access logs and alerts.

### Result: NAS protected from ransomware and external attacks.

---

## Virus & Malware Protection

| Platform | Tools & Actions |
| :--- | :--- |
| **Linux** | ClamAV (scheduled scans), Wordfence malware detection |
| **Windows** | Microsoft Defender, Malwarebytes Endpoint Protection |
| **Testing** | EICAR malware test file |

### Result: Early detection and prevention of malware.

---

## Firewall Configuration (pfSense / Azure Firewall)

### Firewall Placement
The firewall is positioned strategically between the **Internet** and the **Internal Network**.

### Step-by-Step Rules
| Rule | Action | Traffic Flow |
| :--- | :--- | :--- |
| **Allow HTTPS** | Allow |  Web Server |
| **Allow VPN** | Allow |  VPN Gateway |
| **Block SMB** | Block |  Internal |
| **Block RDP** | Block |  Internal |
| **DoS Protection** | Enable | Global |

### Advanced Protection
* Rate limiting.
* SYN flood protection.
* Geo-blocking (optional).

### Result: Strong perimeter defense.

---

## Secure Remote Access (VPN)

* **Tool:** OpenVPN or WireGuard.
* **Installation & Configuration:**
    * Install VPN on firewall.
    * Integrate with Active Directory.
    * Enforce MFA.
    * Assign access based on role.
* **Usage:**
    - Employees connect to VPN.
    - Access NAS, AD, and internal services.

### Result: Encrypted and authenticated remote access.

---

## IDS / IPS Implementation (Snort)

* **Installation:** Installed on firewall or Ubuntu server.
* **Configuration:**
    * Monitor internal and external interfaces.
    * Enable **Emerging Threats** rules.
    * Enable **IPS mode** (block attacks).
* **Logging & Alerts:**
    * Brute force attacks.
    * Port scans.
    * SQL injection.
    * Malware traffic.

### Result: Real-time attack detection and prevention.

---

## Multi-Factor Authentication (MFA)

* **Tools:** Duo Security.
* **Enabled On:**
    * Windows login.
    * VPN access.
    * NAS admin access.
* **Authentication Methods:**
    * Push notification.
    * OTP (One-Time Password).

### Result: Credentials alone cannot compromise systems.

---

## Role-Based Access Control (RBAC)

### Roles Defined
| Role | Access Level |
| :--- | :--- |
| **Admin** | Full access |
| **IT Support** | Servers & logs |
| **Marketing** | Website CMS |
| **Sales** | Limited NAS access |

### Implementation
* Active Directory groups.
* NAS permission mapping.
* VPN access rules.

### Result: Users access only what they need.




