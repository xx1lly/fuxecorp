# Pentest Tool

Ruby-based penetration testing framework with 90+ attack modules.

## Installation

```bash
ruby main.rb
```

## Requirements

- Ruby 2.7+
- Standard library (most modules)
- Optional: net-ssh, winrm (for lateral movement)

## Modules

### Network Testing
- Port Scanning (TCP/UDP, stealth, version detection)
- Network Analysis (ping sweep, traceroute, firewall detection)
- SSL/TLS Analysis (certificate, protocols, heartbleed)
- Service Detection

### Web Application Testing
- SQL Injection (union, boolean, time-based, error-based, blind)
- XSS (reflected, DOM-based, stored)
- Command Injection (OS detection, blind)
- Path Traversal (encoding bypass, null byte)
- RCE (PHP, Python, Ruby, Java, template injection)
- File Upload (MIME bypass, double extension, null byte)
- XXE (blind XXE)
- SSRF (blind SSRF)
- Directory Scanning
- API Testing (CORS, rate limiting, IDOR, parameter pollution)
- GraphQL Injection (introspection, SQLi, aliases)
- WebSocket Attacks (CSWSH, DoS, message injection)

### Authentication & Authorization
- Authentication Bypass (SQLi auth, default credentials, session fixation)
- IDOR Testing (sequential IDs, user manipulation, object reference)
- CSRF Testing (protection check, PoC generation, SameSite cookie)
- Session Management (fixation, timeout, hijacking, concurrent)
- JWT Attacks (none algorithm, weak secret, privilege escalation)

### Injection Attacks
- LDAP Injection
- NoSQL Injection (MongoDB, CouchDB)
- Template Injection (Jinja2, FreeMarker, Velocity, Smarty, Twig)
- Deserialization (Java, PHP, Python, Ruby)
- Prototype Pollution (URL, JSON, DOM XSS, RCE)

### Advanced Attacks
- HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)
- Cache Poisoning (host header, unkeyed headers, cache deception)
- Open Redirect (parameter-based, header-based)
- Clickjacking (protection test, PoC generation)
- Mass Assignment (form, JSON)
- Timing Attacks (username enumeration)
- Padding Oracle (CBC padding)
- CRLF Injection (header injection, log poisoning)
- Insecure Random (weak random, session entropy)

### Social Engineering
- Phishing (page generation, cloning, QR codes, email templates)
- Social Engineering (credential harvesters, phone spoofing, SMS phishing, pretexts)
- Email Spoofing (SPF/DKIM/DMARC testing, spear phishing)
- Malware Generator (PowerShell/VBS/Batch droppers, macros, HTA, persistence)
- Credential Harvesting (keyloggers, form grabbers, cookie stealers, session hijackers)

### Information Gathering
- WHOIS, DNS Lookup, Reverse DNS
- Subdomain Enumeration
- IP Geolocation
- Banner Grabbing
- OS Detection
- Advanced Recon (Shodan, Censys, VirusTotal, Wayback Machine, Certificate Transparency)

### Password Attacks
- Password Cracking (hash cracking, dictionary attacks, rainbow tables, mask bruteforce)
- Bruteforce (FTP, SSH, HTTP, WordPress, MySQL, PostgreSQL, SMTP)

### Post-Exploitation
- Exploit Chains (full chain generation, privilege escalation)
- Lateral Movement (internal network scan, SSH/SMB/WinRM/RDP, remote execution)
- Persistence (Windows/Linux/Web persistence, backdoor accounts)
- Data Exfiltration (DNS/HTTP/ICMP exfiltration, exfiltration servers)
- Post Exploitation (recon scripts, credential harvesters, network sniffers, keyloggers)
- Evasion (payload obfuscation, polymorphic payloads, WAF/IPS/AV evasion)

### Advanced Attacks
- Zero-Day Exploits (Log4j, Spring4Shell, Apache Struts, Apache Solr, Ghostcat)
- C2 Framework (C2 server/client, HTTP C2, command & control)
- Ransomware (encryption key generation, ransomware scripts, ransom notes)
- Botnet (botnet server/client, DDoS scripts)
- Crypto Mining (miner scripts, browser miners, persistence miners)
- Rootkit (Linux/Windows rootkits, process hiders)
- Memory Attacks (buffer overflow, ROP chains, heap spray, format string)
- Wireless Attacks (WiFi deauth, capture, WPS attacks, evil twin)
- Bluetooth Attacks (scanning, spoofing, bluebug)
- IoT Attacks (device scanning, default credentials, MQTT, telnet)
- Mobile Attacks (Android/iOS backdoors, SMS interceptor, location tracker)
- Cloud Attacks (AWS/Azure/GCP bucket testing, metadata services, credential harvesting)
- Container Attacks (Docker/Kubernetes escape, container breakout, socket access)

### Utilities
- Wordlist Generator (base word, common passwords, date-based, permutations, leet speak)
- Payload Generator (reverse/bind shells, web shells, obfuscation, polyglot)
- Exploits (payload generation, exploit search, Metasploit modules)
- Cryptography (hashing, encryption, key generation, hash identification)
- Fuzzing (parameters, paths, headers, methods, values)
- Automation (full web scan, port scan, reconnaissance, vulnerability assessment)
- Reporting (JSON, CSV, Markdown export)

## Usage

1. Run `ruby main.rb`
2. Select module from menu
3. Follow prompts
4. Results saved to reporter
5. Export reports via Reporting menu

## Structure

```
lib/
  core/          - Scanner, Bruteforcer, Reporter
  modules/       - Attack modules
  utils/         - Network, Colorize, Crypto, Logger
```

## Notes

- Use only on systems you own or have permission to test
- Some modules require external services/APIs
- Results logged automatically
- All payloads generated locally

