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
This guide is formatted to be a clean, technical README or instruction set for a GitHub repository.

### pfSense Firewall – Installation, Configuration & Testing

This document provides a comprehensive guide for setting up and hardening a pfSense firewall within a virtualized or physical environment.

### Step 1: Install pfSense

### 1. Prerequisites
* **Download:** Obtain the latest pfSense ISO from [Netgate](https://www.pfsense.org/download/).
* **Resources:** * 2 GB RAM
    * 2 CPUs
    * 20 GB Disk Space

### 2. Network Configuration
Configure the Virtual Machine (VirtualBox / VMware) with **two** Network Interface Cards (NICs):

| Interface | Type | Purpose |
| :--- | :--- | :--- |
| **Adapter 1 (WAN)** | NAT / Bridged | External Internet Connection |
| **Adapter 2 (LAN)** | Internal Network | Private Network Segment |

### 3. Installation Flow
1. Boot from the ISO.
2. Follow the setup wizard using **Default Options**.
3. **Assign Interfaces:**
    * Assign the Internet-facing NIC to **WAN**.
    * Assign the internal network NIC to **LAN**.

### Step 2: Basic Firewall Hardening

To ensure the management interface is secure, perform the following immediately after installation:

- **Change Admin Password:** Replace the default `pfsense` credentials.
- **Disable WebGUI on WAN:** Ensure the management interface is not accessible from the public internet.
- **Enable HTTPS WebGUI:** Force encrypted connections for the dashboard.
- **Enable Automatic Updates:** Maintain the latest security patches.

### Step 3: Firewall Rule Configuration (Core Rules)

#### WAN Rules (Default Deny)
*Primary Goal: Block all unsolicited inbound traffic.*

* **Block:** ALL inbound traffic by default.
* **Allow:** * **WireGuard VPN:** Port `UDP 51820`.
    * **ICMP:** Optional (rate-limited) for diagnostic pings.

#### LAN Rules
*Primary Goal: Restrict internal traffic to necessary services.*

* **Allow:**
    * LAN → VPN subnet.
    * LAN → Web Server (Ports `80`, `443`).
    * LAN → DNS (Port `53`), NTP (Port `123`).
* **Deny:**
    * SMB (`445`), RDP (`3389`), SSH (`22`) outbound to the general internet.

#### Anti-DDoS & Brute Force

Implement **Firewall Limiters** to mitigate volumetric attacks and resource exhaustion:

1. **Navigation:** Go to `Firewall` → `Traffic Shaper` → `Limiters`.
2. **Rate Limiting:**
    * Set **Max 50 connections** per source IP.
    * **Action:** Automatically block the source if the threshold is exceeded.

> Always test your rules after application to ensure legitimate traffic (like DNS lookups) is not inadvertently blocked.

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

## Secure Remote Access (VPN)

* **Tool:** WireGuard.
### WireGuard VPN – Secure Remote Access

This guide covers the installation and configuration of WireGuard on a pfSense firewall to provide encrypted, high-performance remote access to the internal network.

* **Installation & Configuration:**
    * Install VPN on firewall.
    * Integrate with Active Directory.
    * Enforce MFA.
    * Assign access based on role.
* **Usage:**
    - Employees connect to VPN.
    - Access NAS, AD, and internal services.

### Step 1: Install WireGuard

WireGuard is available as a package for pfSense. 

1. Navigate to **System** → **Package Manager** → **Available Packages**.
2. Search for `WireGuard`.
3. Click **Install** and confirm.

---

### Step 2: VPN Configuration

### 1. Create Tunnel
* **Interface:** `wg0`
* **Description:** Remote Access VPN
* **Listen Port:** `51820` (Default)

### 2. Security & Networking
* **Generate Keys:** Create the Server Private and Public keys within the tunnel settings.
* **Assign VPN Subnet:** * Tunnel Address: `10.10.10.1/24`
    * This subnet will be used for all connected VPN clients.

### Step 3: Client Configuration

Each client requires a unique configuration file. Below is a standard template for a remote employee:

ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.10.10.10/32
DNS = 10.0.0.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <YOUR_PUBLIC_IP>:51820
AllowedIPs = 10.0.0.0/16
PersistentKeepalive = 25
[!NOTE] Ensure the Endpoint uses your firewall's public-facing static IP or Dynamic DNS hostname.

### Step 4: VPN Testing
Once the tunnel is active, perform the following validation steps to ensure the "Zero Trust" model is working:

- Connectivity: Ping internal server IPs (e.g., 10.0.0.5) from the client device.
- Resource Access: Attempt to mount an internal file share or access a private web dashboard.
- Security Verification: Disconnect the VPN and verify that all internal resources are completely inaccessible.

### Result: Encrypted and authenticated remote access is established.

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




