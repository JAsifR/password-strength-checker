#!/usr/bin/env python3
"""
Advanced Password Strength Checker
Analyses password strength using entropy calculation, crack time
estimation, character analysis and Have I Been Pwned breach lookup.
Author: [Jahid]
"""

import re
import string
import math
import hashlib
import requests
import secrets

def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def calculate_entropy(password):
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in string.punctuation for c in password): pool += 32
    if pool == 0:
        return 0
    return round(len(password) * math.log2(pool), 2)

def estimate_crack_time(entropy):
    guesses_per_second = 1_000_000_000
    seconds = (2 ** entropy) / guesses_per_second
    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds/86400)} days"
    elif seconds < 3153600000:
        return f"{int(seconds/31536000)} years"
    else:
        return f"{int(seconds/31536000):,} years (practically uncrackable)"

def check_hibp(password):
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "PasswordChecker-Portfolio-Project"},
            timeout=5
        )
        for line in response.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return None

def check_password(password):
    score = 0
    feedback = []

    print(f"\n{'='*55}")
    print(f"  Advanced Password Strength Checker")
    print(f"{'='*55}\n")

    # Common passwords
    COMMON_PASSWORDS = [
        "password", "123456", "password123", "admin", "letmein",
        "qwerty", "monkey", "1234567890", "iloveyou", "welcome",
        "123456789", "12345678", "12345", "1234567", "dragon",
        "master", "sunshine", "princess", "login", "passw0rd"
    ]
    if password.lower() in COMMON_PASSWORDS:
        print("  [FAIL] This is one of the most common passwords ever.")
        print("  Strength: VERY WEAK ❌")
        print(f"\n  💡 Suggested strong password: {generate_strong_password()}")
        print(f"\n{'='*55}\n")
        return

    # Length
    if len(password) >= 16:
        score += 2
    elif len(password) >= 12:
        score += 1
    else:
        feedback.append("  x Use at least 12 characters (16+ is ideal)")

    # Character variety
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("  x Add uppercase letters (A-Z)")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("  x Add lowercase letters (a-z)")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("  x Add numbers (0-9)")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("  x Add special characters (!@#$%^&*)")

    # Patterns
    if re.search(r'(.)\1\1', password):
        score -= 1
        feedback.append("  x Avoid repeated characters (aaa, 111)")
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
        score -= 1
        feedback.append("  x Avoid sequential patterns (123, abc)")

    # Entropy
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    # Strength label
    if score >= 6:
        strength = "VERY STRONG ✅"
    elif score >= 4:
        strength = "STRONG"
    elif score >= 3:
        strength = "MODERATE"
    elif score >= 2:
        strength = "WEAK"
    else:
        strength = "VERY WEAK ❌"

    print(f"  Strength   : {strength}")
    print(f"  Score      : {max(score, 0)}/7")
    print(f"  Entropy    : {entropy} bits")
    print(f"  Crack Time : {crack_time} (at 1 billion guesses/sec)")

    # HIBP check
    print(f"\n  Checking breach databases...")
    pwned_count = check_hibp(password)
    if pwned_count is None:
        print(f"  Breach Check : Could not connect to breach database")
    elif pwned_count > 0:
        print(f"  Breach Check : FOUND IN {pwned_count:,} DATA BREACHES - DO NOT USE!")
    else:
        print(f"  Breach Check : Not found in any known data breaches")

    if feedback:
        print(f"\n  Improvements needed:")
        for tip in feedback:
            print(tip)

    if score < 4:
        print(f"\n  Suggested strong password: {generate_strong_password()}")

    print(f"\n{'='*55}\n")


print("\n*** Passwords are not stored or transmitted ***")
print("*** Your password is hashed locally before any check ***\n")

while True:
    try:
        password = input("Enter a password to check (or type 'quit'): ")
        if password.lower() == 'quit':
            print("\nGoodbye!\n")
            break
        if password.strip() == "":
            print("Please enter a password.\n")
            continue
        check_password(password)
    except KeyboardInterrupt:
        print("\n\nExited.\n")
        break