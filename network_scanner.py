import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import re

class NetworkVulnerabilityScanner:
    """
    Network vulnerability scanner using Nmap for port scanning and service detection.
    Identifies misconfigurations and generates risk assessment reports.
    """
    
    def __init__(self):
        # Risk levels for different services and configurations
        self.high_risk_ports = {
            21: "FTP (Unencrypted file transfer)",
            23: "Telnet (Unencrypted remote access)",
            25: "SMTP (Mail server - check if open relay)",
            69: "TFTP (Trivial File Transfer - no authentication)",
            135: "RPC (Remote Procedure Call - exploit target)",
            139: "NetBIOS (SMB without encryption)",
            445: "SMB (File sharing - check for vulnerabilities)",
            1433: "MS SQL Server (Database - check authentication)",
            3306: "MySQL (Database - check authentication)",
            3389: "RDP (Remote Desktop - brute force target)",
            5900: "VNC (Remote desktop - often weak passwords)",
            6379: "Redis (Database - often no authentication)"
        }
        
        self.medium_risk_ports = {
            80: "HTTP (Unencrypted web traffic)",
            8080: "HTTP Proxy (Unencrypted)",
            8000: "HTTP Alternative (Unencrypted)",
            5432: "PostgreSQL (Database)",
            27017: "MongoDB (NoSQL Database)",
            9200: "Elasticsearch (Search engine)"
        }
        
        self.secure_alternatives = {
            21: "Use SFTP (port 22) or FTPS instead",
            23: "Use SSH (port 22) instead",
            80: "Use HTTPS (port 443) instead",
            8080: "Use HTTPS with proper TLS configuration"
        }
        
    def check_nmap_installed(self):
        """Check if Nmap is installed on the system"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan_network(self, target, scan_type='quick'):
        """
        Perform network scan using Nmap
        
        Args:
            target: IP address or hostname to scan (e.g., '192.168.1.1' or 'scanme.nmap.org')
            scan_type: 'quick', 'full', or 'service'
        """
        print(f"\n🔍 Starting {scan_type} scan on target: {target}")
        print(f"⏰ Scan initiated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Build Nmap command based on scan type
        if scan_type == 'quick':
            # Quick scan: Top 1000 ports
            nmap_cmd = ['nmap', '-T4', '-F', target]
        elif scan_type == 'full':
            # Full scan: All ports with service detection
            nmap_cmd = ['nmap', '-p-', '-sV', '-T4', target]
        elif scan_type == 'service':
            # Service detection scan with OS detection
            nmap_cmd = ['nmap', '-sV', '-sC', '-O', '-T4', target]
        else:
            nmap_cmd = ['nmap', '-T4', target]
        
        try:
            # Run Nmap scan
            result = subprocess.run(nmap_cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300)
            
            if result.returncode == 0:
                return self.parse_nmap_output(result.stdout, target)
            else:
                print(f"⚠️ Nmap scan failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            print("⚠️ Scan timed out after 5 minutes")
            return None
        except Exception as e:
            print(f"⚠️ Error during scan: {str(e)}")
            return None
    
    def parse_nmap_output(self, output, target):
        """Parse Nmap text output and extract relevant information"""
        scan_results = {
            'target': target,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports_count': 0,
            'host_status': 'unknown',
            'os_detection': None
        }
        
        lines = output.split('\n')
        
        for line in lines:
            # Check host status
            if 'Host is up' in line:
                scan_results['host_status'] = 'up'
            
            # Parse open/filtered ports
            port_match = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(\w+)\s*(.*)', line)
            if port_match:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5).strip() if port_match.group(5) else ''
                
                port_info = {
                    'port': port_num,
                    'protocol': protocol,
                    'state': state,
                    'service': service,
                    'version': version
                }
                
                if state == 'open':
                    scan_results['open_ports'].append(port_info)
                elif state == 'filtered':
                    scan_results['filtered_ports'].append(port_info)
            
            # Extract OS detection if available
            if 'OS details:' in line or 'Running:' in line:
                scan_results['os_detection'] = line.strip()
        
        return scan_results
    
    def assess_risks(self, scan_results):
        """
        Assess security risks based on scan results
        """
        if not scan_results:
            return None
        
        risk_assessment = {
            'target': scan_results['target'],
            'assessment_time': scan_results['scan_time'],
            'overall_risk_level': 'LOW',
            'high_risk_findings': [],
            'medium_risk_findings': [],
            'low_risk_findings': [],
            'misconfigurations': [],
            'recommendations': []
        }
        
        # Analyze each open port
        for port_info in scan_results['open_ports']:
            port = port_info['port']
            service = port_info['service']
            
            # Check for high-risk services
            if port in self.high_risk_ports:
                finding = {
                    'port': port,
                    'service': service,
                    'description': self.high_risk_ports[port],
                    'severity': 'HIGH'
                }
                risk_assessment['high_risk_findings'].append(finding)
                risk_assessment['overall_risk_level'] = 'HIGH'
                
                # Add specific misconfigurations
                if port == 21:  # FTP
                    risk_assessment['misconfigurations'].append({
                        'issue': 'FTP without encryption detected',
                        'port': port,
                        'impact': 'Credentials and data transmitted in cleartext',
                        'recommendation': self.secure_alternatives.get(port, 'Disable or secure this service')
                    })
                
                elif port == 23:  # Telnet
                    risk_assessment['misconfigurations'].append({
                        'issue': 'Telnet service detected',
                        'port': port,
                        'impact': 'All traffic including passwords sent unencrypted',
                        'recommendation': self.secure_alternatives.get(port, 'Disable or secure this service')
                    })
                
                elif port == 445:  # SMB
                    risk_assessment['misconfigurations'].append({
                        'issue': 'SMB service exposed',
                        'port': port,
                        'impact': 'Vulnerable to EternalBlue and ransomware attacks',
                        'recommendation': 'Enable SMB signing, use SMB3 with encryption'
                    })
                
                elif port == 3389:  # RDP
                    risk_assessment['misconfigurations'].append({
                        'issue': 'RDP service exposed to network',
                        'port': port,
                        'impact': 'Target for brute force attacks',
                        'recommendation': 'Use VPN, implement account lockout, enable NLA'
                    })
            
            # Check for medium-risk services
            elif port in self.medium_risk_ports:
                finding = {
                    'port': port,
                    'service': service,
                    'description': self.medium_risk_ports[port],
                    'severity': 'MEDIUM'
                }
                risk_assessment['medium_risk_findings'].append(finding)
                
                if risk_assessment['overall_risk_level'] == 'LOW':
                    risk_assessment['overall_risk_level'] = 'MEDIUM'
                
                if port == 80:  # HTTP
                    risk_assessment['misconfigurations'].append({
                        'issue': 'HTTP without encryption',
                        'port': port,
                        'impact': 'Data transmitted in cleartext, vulnerable to MITM attacks',
                        'recommendation': self.secure_alternatives.get(port, 'Enable HTTPS')
                    })
            
            # All other open ports
            else:
                finding = {
                    'port': port,
                    'service': service,
                    'description': f'{service} service running',
                    'severity': 'LOW'
                }
                risk_assessment['low_risk_findings'].append(finding)
        
        # Generate overall recommendations
        risk_assessment['recommendations'] = self.generate_recommendations(risk_assessment)
        
        return risk_assessment
    
    def generate_recommendations(self, risk_assessment):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if risk_assessment['high_risk_findings']:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Immediately disable or secure high-risk services',
                'details': 'Services like FTP, Telnet, and unencrypted protocols should be replaced with secure alternatives'
            })
        
        if risk_assessment['misconfigurations']:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Fix identified misconfigurations',
                'details': 'Review each misconfiguration and apply recommended fixes'
            })
        
        recommendations.extend([
            {
                'priority': 'HIGH',
                'action': 'Implement firewall rules',
                'details': 'Block unnecessary ports and restrict access to required services only'
            },
            {
                'priority': 'MEDIUM',
                'action': 'Enable encryption for all data transmission',
                'details': 'Use TLS/SSL for web services, SSH for remote access, and encrypted protocols for file transfers'
            },
            {
                'priority': 'MEDIUM',
                'action': 'Regular security audits',
                'details': 'Schedule periodic vulnerability scans and penetration tests'
            },
            {
                'priority': 'LOW',
                'action': 'Monitor network traffic',
                'details': 'Implement IDS/IPS solutions to detect and prevent attacks'
            }
        ])
        
        return recommendations
    
    def generate_risk_report(self, risk_assessment):
        """Generate comprehensive risk assessment report"""
        if not risk_assessment:
            return None
        
        print("\n" + "="*80)
        print("  NETWORK VULNERABILITY SCAN - RISK ASSESSMENT REPORT")
        print("="*80)
        print(f"Target: {risk_assessment['target']}")
        print(f"Assessment Time: {risk_assessment['assessment_time']}")
        print(f"Overall Risk Level: {risk_assessment['overall_risk_level']}")
        print("\n" + "-"*80)
        print("EXECUTIVE SUMMARY")
        print("-"*80)
        
        total_findings = (len(risk_assessment['high_risk_findings']) + 
                         len(risk_assessment['medium_risk_findings']) + 
                         len(risk_assessment['low_risk_findings']))
        
        print(f"Total Security Findings: {total_findings}")
        print(f"  • High Risk:   {len(risk_assessment['high_risk_findings'])}")
        print(f"  • Medium Risk: {len(risk_assessment['medium_risk_findings'])}")
        print(f"  • Low Risk:    {len(risk_assessment['low_risk_findings'])}")
        print(f"  • Misconfigurations: {len(risk_assessment['misconfigurations'])}")
        
        # High Risk Findings
        if risk_assessment['high_risk_findings']:
            print("\n" + "-"*80)
            print("🚨 HIGH RISK FINDINGS")
            print("-"*80)
            for finding in risk_assessment['high_risk_findings']:
                print(f"\n⚠️  Port {finding['port']}/{finding['service']}")
                print(f"   Description: {finding['description']}")
                print(f"   Severity: {finding['severity']}")
        
        # Medium Risk Findings
        if risk_assessment['medium_risk_findings']:
            print("\n" + "-"*80)
            print("⚠️  MEDIUM RISK FINDINGS")
            print("-"*80)
            for finding in risk_assessment['medium_risk_findings']:
                print(f"\n   Port {finding['port']}/{finding['service']}")
                print(f"   Description: {finding['description']}")
        
        # Misconfigurations
        if risk_assessment['misconfigurations']:
            print("\n" + "-"*80)
            print("🔧 IDENTIFIED MISCONFIGURATIONS")
            print("-"*80)
            for i, misconfig in enumerate(risk_assessment['misconfigurations'], 1):
                print(f"\n{i}. {misconfig['issue']}")
                print(f"   Port: {misconfig['port']}")
                print(f"   Impact: {misconfig['impact']}")
                print(f"   Recommendation: {misconfig['recommendation']}")
        
        # Recommendations
        print("\n" + "-"*80)
        print("💡 SECURITY RECOMMENDATIONS")
        print("-"*80)
        for i, rec in enumerate(risk_assessment['recommendations'], 1):
            print(f"\n{i}. [{rec['priority']}] {rec['action']}")
            print(f"   {rec['details']}")
        
        print("\n" + "="*80)
        print("END OF RISK ASSESSMENT REPORT")
        print("="*80 + "\n")
        
        return risk_assessment
    
    def save_report_json(self, risk_assessment, filename='risk_assessment_report.json'):
        """Save risk assessment report to JSON file"""
        with open(filename, 'w') as f:
            json.dump(risk_assessment, f, indent=2)
        print(f"📄 Report saved to: {filename}")


# Example usage and testing
if __name__ == "__main__":
    scanner = NetworkVulnerabilityScanner()
    
    print("\n🛡️  NETWORK VULNERABILITY SCANNER")
    print("="*80)
    
    # Check if Nmap is installed
    if not scanner.check_nmap_installed():
        print("\n⚠️  WARNING: Nmap is not installed or not in PATH")
        print("To install Nmap:")
        print("  • Ubuntu/Debian: sudo apt-get install nmap")
        print("  • macOS: brew install nmap")
        print("  • Windows: Download from https://nmap.org/download.html")
        print("\nProceeding with simulated scan for demonstration...\n")
        
        # Simulated scan results for demonstration
        scan_results = {
            'target': '192.168.1.100',
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': [
                {'port': 21, 'protocol': 'tcp', 'state': 'open', 'service': 'ftp', 'version': 'vsftpd 3.0.3'},
                {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2'},
                {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'version': 'Apache 2.4.41'},
                {'port': 445, 'protocol': 'tcp', 'state': 'open', 'service': 'microsoft-ds', 'version': ''},
                {'port': 3306, 'protocol': 'tcp', 'state': 'open', 'service': 'mysql', 'version': 'MySQL 5.7'},
                {'port': 3389, 'protocol': 'tcp', 'state': 'open', 'service': 'ms-wbt-server', 'version': ''}
            ],
            'filtered_ports': [],
            'closed_ports_count': 0,
            'host_status': 'up',
            'os_detection': 'Linux 3.2 - 4.9'
        }
        
        print("📊 Simulated Scan Results:")
        print(f"Target: {scan_results['target']}")
        print(f"Status: {scan_results['host_status']}")
        print(f"Open Ports: {len(scan_results['open_ports'])}")
        
    else:
        # Real scan - Use scanme.nmap.org (officially sanctioned for testing)
        print("\n✅ Nmap is installed")
        print("\nScanning 'scanme.nmap.org' (authorized test target)...")
        scan_results = scanner.scan_network('scanme.nmap.org', 'quick')
    
    # Perform risk assessment
    if scan_results:
        risk_assessment = scanner.assess_risks(scan_results)
        
        # Generate and display report
        scanner.generate_risk_report(risk_assessment)
        
        # Save to JSON
        scanner.save_report_json(risk_assessment)
    else:
        print("\n⚠️  Unable to complete scan")
    
    print("\n💡 NOTE: Always ensure you have permission before scanning any network!")
    print("Unauthorized network scanning may be illegal in your jurisdiction.\n")