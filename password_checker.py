#!/usr/bin/env python3
"""
PRODIGY_CS_03: Advanced Password Complexity Checker
====================================================
A comprehensive password strength assessment tool that evaluates passwords
based on multiple security criteria and provides actionable feedback.

Author: Amit Mondal - Cybersecurity Intern - Prodigy InfoTech
Date: June 2025
Version: 1.0

Features:
- CLI interface
- Entropy calculation using information theory
- Pattern detection for keyboard sequences, repetition, common passwords
- Real-time analysis with 0-15 point scoring system
"""

import re
import math
import string
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class PasswordStrength(Enum):
    """Enumeration for password strength levels"""
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass
class PasswordCriteria:
    """Data class to store password analysis results"""
    length_score: int
    uppercase_present: bool
    lowercase_present: bool
    digits_present: bool
    special_chars_present: bool
    entropy: float
    common_patterns: List[str]
    total_score: int
    strength: PasswordStrength


class AdvancedPasswordChecker:
    """
    Advanced password complexity checker with entropy calculation,
    pattern detection, and comprehensive security analysis
    """
    
    def __init__(self):
        # Common weak patterns to detect
        self.weak_patterns = [
            r'(.)\1{2,}',  # Repeated characters (3+ times)
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
            r'(qwer|asdf|zxcv|yuio|hjkl)',  # Keyboard patterns
        ]
        
        # Common weak passwords (simplified list)
        self.common_passwords = {
            'password', 'password123', '123456', '123456789', 'qwerty',
            'abc123', 'password1', 'admin', 'letmein', 'welcome'
        }
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy based on character space and length
        Entropy = log2(character_space^length)
        """
        char_space = 0
        
        if re.search(r'[a-z]', password):
            char_space += 26  # lowercase letters
        if re.search(r'[A-Z]', password):
            char_space += 26  # uppercase letters
        if re.search(r'[0-9]', password):
            char_space += 10  # digits
        if re.search(r'[^a-zA-Z0-9]', password):
            char_space += 32  # special characters (approximate)
        
        if char_space == 0:
            return 0
        
        entropy = len(password) * math.log2(char_space)
        return round(entropy, 2)
    
    def detect_patterns(self, password: str) -> List[str]:
        """Detect common weak patterns in password"""
        detected_patterns = []
        
        # Check for weak patterns
        for pattern in self.weak_patterns:
            if re.search(pattern, password.lower()):
                if 'repeated' not in str(detected_patterns):
                    if re.search(r'(.)\1{2,}', password):
                        detected_patterns.append("Repeated characters")
                if 'sequential' not in str(detected_patterns):
                    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
                        detected_patterns.append("Sequential patterns")
                if 'keyboard' not in str(detected_patterns):
                    if re.search(r'(qwer|asdf|zxcv)', password.lower()):
                        detected_patterns.append("Keyboard patterns")
        
        # Check for common passwords
        if password.lower() in self.common_passwords:
            detected_patterns.append("Common password")
        
        # Check for simple dictionary words (basic check)
        if len(password) > 3 and password.lower().isalpha():
            detected_patterns.append("Dictionary word")
        
        return detected_patterns
    
    def calculate_length_score(self, password: str) -> int:
        """Calculate score based on password length"""
        length = len(password)
        if length < 6:
            return 0
        elif length < 8:
            return 1
        elif length < 12:
            return 2
        elif length < 16:
            return 3
        else:
            return 4
    
    def analyze_password(self, password: str) -> PasswordCriteria:
        """
        Comprehensive password analysis
        Returns PasswordCriteria object with detailed analysis
        """
        if not password:
            return PasswordCriteria(0, False, False, False, False, 0, [], 0, PasswordStrength.VERY_WEAK)
        
        # Basic criteria checks
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        # Calculate scores
        length_score = self.calculate_length_score(password)
        entropy = self.calculate_entropy(password)
        patterns = self.detect_patterns(password)
        
        # Calculate total score
        total_score = length_score
        total_score += 2 if has_upper else 0
        total_score += 2 if has_lower else 0
        total_score += 2 if has_digit else 0
        total_score += 3 if has_special else 0
        
        # Bonus for high entropy
        if entropy > 60:
            total_score += 2
        elif entropy > 40:
            total_score += 1
        
        # Penalty for weak patterns
        total_score -= len(patterns)
        total_score = max(0, total_score)  # Ensure non-negative
        
        # Determine strength level
        if total_score <= 2:
            strength = PasswordStrength.VERY_WEAK
        elif total_score <= 5:
            strength = PasswordStrength.WEAK
        elif total_score <= 8:
            strength = PasswordStrength.MODERATE
        elif total_score <= 12:
            strength = PasswordStrength.STRONG
        else:
            strength = PasswordStrength.VERY_STRONG
        
        return PasswordCriteria(
            length_score=length_score,
            uppercase_present=has_upper,
            lowercase_present=has_lower,
            digits_present=has_digit,
            special_chars_present=has_special,
            entropy=entropy,
            common_patterns=patterns,
            total_score=total_score,
            strength=strength
        )
    
    def generate_feedback(self, criteria: PasswordCriteria) -> str:
        """Generate detailed feedback based on password analysis"""
        feedback = []
        
        # Strength assessment
        feedback.append(f"🔒 Password Strength: {criteria.strength.value}")
        feedback.append(f"📊 Security Score: {criteria.total_score}/15")
        feedback.append(f"🧮 Entropy: {criteria.entropy} bits")
        feedback.append("")
        
        # Detailed analysis
        feedback.append("📋 ANALYSIS BREAKDOWN:")
        feedback.append("─" * 40)
        
        # Length analysis
        length_feedback = {
            0: "❌ Too short (< 6 characters) - CRITICAL",
            1: "⚠️  Short (6-7 characters) - Add more",
            2: "✅ Adequate (8-11 characters)",
            3: "✅ Good (12-15 characters)",
            4: "✅ Excellent (16+ characters)"
        }
        feedback.append(f"Length: {length_feedback[criteria.length_score]}")
        
        # Character type analysis
        feedback.append(f"Uppercase: {'✅ Present' if criteria.uppercase_present else '❌ Missing'}")
        feedback.append(f"Lowercase: {'✅ Present' if criteria.lowercase_present else '❌ Missing'}")
        feedback.append(f"Numbers: {'✅ Present' if criteria.digits_present else '❌ Missing'}")
        feedback.append(f"Special chars: {'✅ Present' if criteria.special_chars_present else '❌ Missing'}")
        
        # Pattern warnings
        if criteria.common_patterns:
            feedback.append("")
            feedback.append("⚠️  SECURITY WARNINGS:")
            for pattern in criteria.common_patterns:
                feedback.append(f"   • {pattern} detected")
        
        # Recommendations
        feedback.append("")
        feedback.append("💡 RECOMMENDATIONS:")
        recommendations = self.get_recommendations(criteria)
        for rec in recommendations:
            feedback.append(f"   • {rec}")
        
        return "\n".join(feedback)
    
    def get_recommendations(self, criteria: PasswordCriteria) -> List[str]:
        """Generate specific recommendations for password improvement"""
        recommendations = []
        
        if criteria.length_score < 2:
            recommendations.append("Increase length to at least 8 characters")
        elif criteria.length_score < 3:
            recommendations.append("Consider using 12+ characters for better security")
        
        if not criteria.uppercase_present:
            recommendations.append("Add uppercase letters (A-Z)")
        
        if not criteria.lowercase_present:
            recommendations.append("Add lowercase letters (a-z)")
        
        if not criteria.digits_present:
            recommendations.append("Include numbers (0-9)")
        
        if not criteria.special_chars_present:
            recommendations.append("Add special characters (!@#$%^&*)")
        
        if criteria.common_patterns:
            recommendations.append("Avoid predictable patterns and common passwords")
        
        if criteria.entropy < 40:
            recommendations.append("Increase complexity for higher entropy")
        
        if criteria.strength in [PasswordStrength.VERY_STRONG, PasswordStrength.STRONG]:
            recommendations.append("Great password! Consider using a password manager")
        
        return recommendations


def display_banner():
    """Display application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                  ADVANCED PASSWORD ANALYZER                   ║
║                 PRODIGY_CS_03 - Version 1.0                   ║
║                                                               ║
║            🔐 Cybersecurity Internship Project 🔐             ║
║                        Prodigy InfoTech                       ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main application function"""
    display_banner()
    
    checker = AdvancedPasswordChecker()
    
    print("Welcome to the Advanced Password Complexity Checker!")
    print("This tool will analyze your password's security strength.\n")
    
    while True:
        try:
            # Get password input (hidden for security)
            import getpass
            password = getpass.getpass("Enter password to analyze (or 'quit' to exit): ")
            
            if password.lower() in ['quit', 'exit', 'q']:
                print("\n👋 Thank you for using Password Analyzer!")
                break
            
            if not password:
                print("❌ Please enter a password to analyze.\n")
                continue
            
            # Analyze password
            print("\n🔍 Analyzing password...")
            criteria = checker.analyze_password(password)
            
            # Display results
            print("\n" + "="*60)
            print(checker.generate_feedback(criteria))
            print("="*60)
            
            # Ask for another analysis
            another = input("\n🔄 Analyze another password? (y/n): ").lower()
            if another not in ['y', 'yes']:
                break
            
            print()  # Add spacing
            
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ An error occurred: {e}")
            print("Please try again.\n")


if __name__ == "__main__":
    main()