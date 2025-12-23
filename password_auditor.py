import re
import json
from datetime import datetime

class PasswordStrengthAuditor:
    """
    A comprehensive password strength auditor that validates passwords against
    security policies and common password databases.
    """
    
    def __init__(self):
        # Common weak passwords list
        self.common_passwords = [
            "password", "123456", "password123", "12345678", "qwerty",
            "abc123", "monkey", "1234567", "letmein", "trustno1",
            "dragon", "baseball", "iloveyou", "master", "sunshine",
            "ashley", "bailey", "passw0rd", "shadow", "123123",
            "654321", "superman", "qazwsx", "michael", "football"
        ]
        
        # Policy requirements
        self.min_length = 8
        self.max_length = 128
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digit = True
        self.require_special = True
        
    def check_length(self, password):
        """Check if password meets length requirements"""
        length = len(password)
        if length < self.min_length:
            return False, f"Password too short (minimum {self.min_length} characters)"
        elif length > self.max_length:
            return False, f"Password too long (maximum {self.max_length} characters)"
        return True, "Length requirement met"
    
    def check_uppercase(self, password):
        """Check for uppercase letters using regex"""
        if self.require_uppercase:
            if re.search(r'[A-Z]', password):
                return True, "Contains uppercase letter"
            return False, "Missing uppercase letter"
        return True, "Uppercase not required"
    
    def check_lowercase(self, password):
        """Check for lowercase letters using regex"""
        if self.require_lowercase:
            if re.search(r'[a-z]', password):
                return True, "Contains lowercase letter"
            return False, "Missing lowercase letter"
        return True, "Lowercase not required"
    
    def check_digit(self, password):
        """Check for digits using regex"""
        if self.require_digit:
            if re.search(r'\d', password):
                return True, "Contains digit"
            return False, "Missing digit"
        return True, "Digit not required"
    
    def check_special_chars(self, password):
        """Check for special characters using regex"""
        if self.require_special:
            if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
                return True, "Contains special character"
            return False, "Missing special character"
        return True, "Special character not required"
    
    def check_common_password(self, password):
        """Check if password is in common passwords list"""
        if password.lower() in self.common_passwords:
            return False, "Password found in common passwords database"
        return True, "Not a common password"
    
    def check_sequential_chars(self, password):
        """Check for sequential characters (e.g., 123, abc)"""
        sequences = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiop']
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in password.lower():
                    return False, f"Contains sequential pattern: {seq[i:i+3]}"
        return True, "No sequential patterns detected"
    
    def check_repeated_chars(self, password):
        """Check for repeated characters (e.g., aaa, 111)"""
        if re.search(r'(.)\1{2,}', password):
            return False, "Contains repeated characters (3+ in a row)"
        return True, "No excessive character repetition"
    
    def calculate_entropy(self, password):
        """Calculate password entropy (strength measure)"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        import math
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def audit_password(self, password):
        """
        Perform complete password audit and return detailed results
        """
        results = {
            'password': password,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'checks': [],
            'passed': True,
            'vulnerability_score': 0,
            'strength_rating': '',
            'entropy': 0
        }
        
        # Run all checks
        checks = [
            ('Length', self.check_length(password)),
            ('Uppercase', self.check_uppercase(password)),
            ('Lowercase', self.check_lowercase(password)),
            ('Digit', self.check_digit(password)),
            ('Special Character', self.check_special_chars(password)),
            ('Common Password', self.check_common_password(password)),
            ('Sequential Pattern', self.check_sequential_chars(password)),
            ('Repeated Characters', self.check_repeated_chars(password))
        ]
        
        # Calculate vulnerability score
        failed_checks = 0
        for check_name, (passed, message) in checks:
            results['checks'].append({
                'check': check_name,
                'passed': passed,
                'message': message
            })
            if not passed:
                failed_checks += 1
                results['passed'] = False
        
        # Calculate scores
        results['vulnerability_score'] = round((failed_checks / len(checks)) * 100, 2)
        results['entropy'] = self.calculate_entropy(password)
        
        # Determine strength rating
        if results['vulnerability_score'] == 0 and results['entropy'] >= 60:
            results['strength_rating'] = 'STRONG'
        elif results['vulnerability_score'] <= 25 and results['entropy'] >= 40:
            results['strength_rating'] = 'MODERATE'
        else:
            results['strength_rating'] = 'WEAK'
        
        return results
    
    def generate_report(self, audit_results_list):
        """
        Generate a comprehensive vulnerability report from multiple password audits
        """
        report = {
            'report_title': 'Password Security Audit Report',
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_passwords_tested': len(audit_results_list),
            'summary': {
                'strong': 0,
                'moderate': 0,
                'weak': 0,
                'average_vulnerability_score': 0
            },
            'detailed_results': audit_results_list
        }
        
        # Calculate summary statistics
        total_vuln_score = 0
        for result in audit_results_list:
            rating = result['strength_rating']
            if rating == 'STRONG':
                report['summary']['strong'] += 1
            elif rating == 'MODERATE':
                report['summary']['moderate'] += 1
            else:
                report['summary']['weak'] += 1
            total_vuln_score += result['vulnerability_score']
        
        report['summary']['average_vulnerability_score'] = round(
            total_vuln_score / len(audit_results_list), 2
        )
        
        return report
    
    def print_report(self, report):
        """Print formatted report to console"""
        print("\n" + "="*70)
        print(f"  {report['report_title']}")
        print("="*70)
        print(f"Generated: {report['generated_at']}")
        print(f"Total Passwords Tested: {report['total_passwords_tested']}")
        print("\n" + "-"*70)
        print("SUMMARY STATISTICS")
        print("-"*70)
        print(f"Strong Passwords:   {report['summary']['strong']}")
        print(f"Moderate Passwords: {report['summary']['moderate']}")
        print(f"Weak Passwords:     {report['summary']['weak']}")
        print(f"Average Vulnerability Score: {report['summary']['average_vulnerability_score']}%")
        
        print("\n" + "-"*70)
        print("DETAILED RESULTS")
        print("-"*70)
        
        for i, result in enumerate(report['detailed_results'], 1):
            print(f"\n[Password #{i}]: {result['password']}")
            print(f"Strength Rating: {result['strength_rating']}")
            print(f"Vulnerability Score: {result['vulnerability_score']}%")
            print(f"Entropy: {result['entropy']} bits")
            print(f"Status: {'✓ PASSED' if result['passed'] else '✗ FAILED'}")
            print("\nCheck Results:")
            for check in result['checks']:
                status = "✓" if check['passed'] else "✗"
                print(f"  {status} {check['check']}: {check['message']}")
        
        print("\n" + "="*70)
        print("END OF REPORT")
        print("="*70 + "\n")


# Example usage and testing
if __name__ == "__main__":
    auditor = PasswordStrengthAuditor()
    
    # Test passwords (including common weak ones)
    test_passwords = [
        "password123",      # Common password
        "P@ssw0rd",         # Missing length, predictable
        "MySecureP@ss123",  # Strong password
        "abc123",           # Common password, too short
        "Test1234",         # Missing special char
        "Str0ng!Pass#2024", # Strong password
        "qwerty",           # Common password
        "A1b2C3d4!@#$",     # Strong password
    ]
    
    print("\n🔐 PASSWORD STRENGTH AUDITOR")
    print("Testing passwords against security policies...\n")
    
    # Audit all passwords
    all_results = []
    for password in test_passwords:
        result = auditor.audit_password(password)
        all_results.append(result)
    
    # Generate and print report
    report = auditor.generate_report(all_results)
    auditor.print_report(report)
    
    # Optional: Save report to JSON file
    with open('password_audit_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("📄 Report also saved to: password_audit_report.json")