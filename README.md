# 🛡️ Cybersecurity Internship Tasks - Sharvas Solutions

## 📋 Overview

This repository contains two comprehensive cybersecurity tools developed as part of the Cybersecurity Internship program at Sharvas Solutions. The projects demonstrate practical skills in password security auditing and network vulnerability assessment.

---

## 📁 Repository Structure

```
cybersecurity-internship-tasks/
│
├── password_auditor.py          # Task 01: Password Strength Auditor
├── network_scanner.py           # Task 02: Network Vulnerability Scanner
├── README.md                    # This file
├── requirements.txt             # Python dependencies
└── sample_reports/              # Sample output reports
    ├── password_audit_report.json
    └── risk_assessment_report.json
```

---

## 🎯 Task 01: Password Strength Auditor

A Python-based tool that validates password policies using regex patterns, tests against common password databases, and generates detailed vulnerability reports.

### Features
- Regex-based validation for length, uppercase, lowercase, digits, and special characters
- Common password detection against weak password database
- Pattern analysis for sequential and repeated characters
- Entropy calculation for password strength measurement
- Vulnerability scoring and JSON report generation

### Tech Stack
- **Language:** Python 3.7+
- **Libraries:** `re`, `json`, `datetime`, `math`

### Usage
```bash
python password_auditor.py
```

### Sample Output
```
🔐 PASSWORD STRENGTH AUDITOR
======================================================================

[Password #1]: password123
Strength Rating: WEAK
Vulnerability Score: 62.5%
Status: ✗ FAILED

Check Results:
  ✓ Length requirement met
  ✗ Missing uppercase letter
  ✗ Missing special character
  ✗ Found in common passwords database
```

---

## 🔍 Task 02: Network Vulnerability Scanner

An automated network security scanner that uses Nmap to identify open ports, detect misconfigured services, and generate comprehensive risk assessment reports.

### Features
- Nmap integration for port scanning and service detection
- Identification of high-risk services (FTP, Telnet, SMB, RDP, VNC)
- Misconfiguration detection for unencrypted protocols
- Risk categorization (HIGH/MEDIUM/LOW) with actionable recommendations
- Console display and JSON export

### Tech Stack
- **Language:** Python 3.7+
- **Tools:** Nmap
- **Libraries:** `subprocess`, `xml.etree.ElementTree`, `json`, `re`

### Usage
```bash
# Install Nmap first
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS

# Run the scanner
python network_scanner.py
```

### Sample Output
```
🛡️ NETWORK VULNERABILITY SCANNER
================================================================================

Target: 192.168.1.100
Overall Risk Level: HIGH

HIGH RISK FINDINGS:
⚠️  Port 21/ftp - Unencrypted file transfer
⚠️  Port 445/microsoft-ds - SMB vulnerability risk
⚠️  Port 3389/ms-wbt-server - RDP brute force target

RECOMMENDATIONS:
• Replace FTP with SFTP or FTPS
• Implement firewall rules to block unnecessary ports
• Enable encryption for all data transmission
```

---

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- Nmap (for network scanner)

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/cybersecurity-internship-tasks.git
cd cybersecurity-internship-tasks

# Install dependencies
pip install -r requirements.txt

# Install Nmap
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

---

## ⚠️ Legal Disclaimer

**Important:** Only scan networks you own or have explicit written permission to test. Unauthorized network scanning may be illegal in your jurisdiction. These tools are created for educational purposes as part of a cybersecurity internship program. Use responsibly and ethically.

---

## 🎓 Learning Outcomes

### Skills Demonstrated
- Password policy enforcement and cryptographic entropy calculation
- Network reconnaissance and vulnerability identification
- Risk assessment methodologies and security best practices
- Object-oriented programming and JSON data handling
- Report generation and documentation

---

## 👨‍💻 Author

**Astha Rawal**
- Internship: Sharvas Solutions - Cybersecurity Program
- LinkedIn: [Aastha Rawal](https://www.linkedin.com/in/aastha-rawal-44a097298/)
- Email: rawal.aastha18@gmail.com
- GitHub: [@Ashh2318](https://github.com/Ashh2318)

---

## 🙏 Acknowledgments

- **Sharvas Solutions** - For providing the internship opportunity
- **Nmap Project** - For the network scanning tool
- **OWASP** - For security best practices and guidelines

---

## 📝 License

This project is created for educational purposes as part of a cybersecurity internship program.

MIT License - Copyright (c) 2024 Astha Rawal

---

## 📞 Contact & Support

- 📧 Email: admin@sharvassolutions.com
- 🌐 Website: [Sharvas Solutions](https://www.sharvassolutions.com/)

---

**Last Updated:** December 23, 2024  
**Status:** ✅ Internship Tasks Complete