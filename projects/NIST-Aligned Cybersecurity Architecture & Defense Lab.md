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
