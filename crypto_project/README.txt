PROJECT: Secure Password Storage and Protection Against Offline Attacks

FILES:
1. insecure_auth.py        -> Insecure password storage using SHA-256 (no salt)
2. secure_auth.py          -> Secure password storage using bcrypt (salted)
3. secure_auth_argon2.py   -> Secure password storage using Argon2id (memory-hard)
4. attack_sha.py           -> Offline dictionary attack on insecure SHA-256 DB
5. attack_bcrypt.py        -> Offline dictionary attack on bcrypt DB
6. attack_argon2.py        -> Offline dictionary attack on Argon2 DB
7. bruteforce_attack.py    -> Brute-force attack on SHA-256 DB
8. bruteforce_bcrypt.py    -> Brute-force attack on bcrypt DB
9. bruteforce_argon2.py    -> Brute-force attack on Argon2 DB
10. rainbow_demo.py        -> Demonstrates same password = same hash without salt
11. benchmark.py           -> SHA-256 vs bcrypt vs Argon2 comparison benchmark
12. test_cases.py          -> Formal test cases for authentication and cracking resistance
13. report.md              -> Project report with analysis and references
14. common_passwords.txt   -> Dictionary wordlist

HOW TO RUN:

1. Install dependencies:
   pip install bcrypt argon2-cffi

2. Run insecure system (SHA-256):
   python insecure_auth.py

3. Run secure system (bcrypt):
   python secure_auth.py

4. Run secure system (Argon2):
   python secure_auth_argon2.py

5. Run dictionary attack on insecure DB:
   python attack_sha.py

6. Run dictionary attack on bcrypt DB:
   python attack_bcrypt.py

7. Run dictionary attack on Argon2 DB:
   python attack_argon2.py

8. Run brute-force on SHA-256 DB:
   python bruteforce_attack.py

9. Run brute-force on bcrypt DB:
   python bruteforce_bcrypt.py

10. Run brute-force on Argon2 DB:
    python bruteforce_argon2.py

11. Run rainbow table demo:
    python rainbow_demo.py

12. Run benchmark comparison (SHA-256 vs bcrypt vs Argon2):
    python benchmark.py

13. Run all test cases:
    python test_cases.py

REFERENCES:
[1] Provos & Mazieres, "A Future-Adaptable Password Scheme" (1999)
    https://www.openbsd.org/papers/bcrypt-paper.pdf

[2] Biryukov, Dinu & Khovratovich, "Argon2: memory-hard function for password hashing" (2016)
    https://www.cryptolux.org/images/0/0d/Argon2.pdf