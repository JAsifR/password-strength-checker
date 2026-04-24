# Advanced Password Strength Checker

A sophisticated password analysis tool using entropy calculation, crack time estimation and real-time breach database lookup via the Have I Been Pwned API.

## Features
- Entropy calculation in bits for true randomness measurement
- Estimated crack time at 1 billion guesses per second
- Have I Been Pwned API integration — checks if password appeared in real data breaches
- Detects sequential patterns, repeated characters and common passwords
- Suggests a strong randomly generated password if weak
- Password never transmitted — hashed locally with SHA-1 before any API call

## Technologies
- Python 3
- hashlib, secrets, math, re, string
- requests (HIBP API)

## Usage
```bash
pip install requests
python password_checker.py
```

## Skills Demonstrated
- Cryptography fundamentals (hashing, entropy)
- API integration with privacy-preserving k-anonymity model
- Cybersecurity awareness and password policy knowledge
- Python scripting
