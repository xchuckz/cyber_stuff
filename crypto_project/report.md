# Secure Password Storage and Protection Against Offline Attacks

## Project Report

---

## 1. Introduction

Password-based authentication remains the most widely used method for securing user accounts. However, the security of a system depends critically on **how passwords are stored**. Storing passwords in plaintext or using weak hashing algorithms exposes users to devastating attacks if the database is compromised.

This project implements and compares three password hashing approaches:
- **SHA-256** (insecure, no salt)
- **bcrypt** (secure, with salt and key stretching)
- **Argon2id** (state-of-the-art, memory-hard with salt and key stretching)

We demonstrate how offline attacks work and why modern algorithms like bcrypt and Argon2 provide significantly better protection.

---

## 2. How Offline Password Attacks Work

### 2.1 Offline Attack Scenario

An offline attack occurs when an attacker gains access to a database containing password hashes. Unlike online attacks (limited by login rate limiting), offline attacks allow the attacker to test billions of password guesses per second on their own hardware, with no restrictions.

**Attack flow:**
1. Attacker steals the database (via SQL injection, data breach, insider threat, etc.)
2. Attacker extracts password hashes
3. Attacker computes hashes of candidate passwords and compares them to stored hashes
4. If a match is found, the plaintext password is recovered

### 2.2 Dictionary Attacks

A dictionary attack uses a precompiled list of commonly used passwords (e.g., "password123", "qwerty", "letmein"). The attacker hashes each word in the dictionary and compares it to the stored hash.

**Why it works:** Studies show that a large percentage of users choose passwords from a relatively small set of common passwords. A dictionary of just 10,000 words can crack a surprising number of accounts.

### 2.3 Brute-Force Attacks

A brute-force attack systematically tries every possible combination of characters up to a certain length. For example, trying all combinations of lowercase letters from length 1 to 8.

**Search space example:**
- 3-character lowercase: 26³ = 17,576 combinations
- 6-character lowercase: 26⁶ = 308,915,776 combinations
- 8-character alphanumeric: 62⁸ = 218 trillion combinations

With SHA-256, an attacker using a modern GPU can compute ~10 billion hashes per second, making short passwords trivially crackable.

### 2.4 Rainbow Table Attacks

A rainbow table is a **precomputed lookup table** that maps hash values back to their plaintext passwords. Instead of computing hashes during the attack, the attacker simply looks up the stolen hash in the table.

**How it works:**
1. Attacker precomputes hashes for millions/billions of passwords
2. Stores them in an optimized table (hash → password)
3. When a database is stolen, looks up each hash in the table
4. Instant password recovery — no computation needed during the attack

**Key vulnerability:** Rainbow tables only work when the same password always produces the **same hash**. This is the case with unsalted algorithms like plain SHA-256.

**Our demonstration (rainbow_demo.py):**
```
Password: password123 --> SHA-256: ef92b778...
Password: password123 --> SHA-256: ef92b778...  (IDENTICAL!)
```

Both users with "password123" have the **exact same hash** — one precomputed table cracks all of them.

---

## 3. The Role of Salts in Password Protection

### 3.1 What is a Salt?

A **salt** is a unique, random value generated for each user and combined with their password before hashing:

```
hash = H(salt + password)
```

The salt is stored alongside the hash (typically embedded in the hash string itself).

### 3.2 How Salts Defeat Rainbow Tables

With salting, even if two users choose the same password, their hashes will be different because each has a unique salt:

```
User A: salt=abc → H("abc" + "password123") = 7f3a9b...
User B: salt=xyz → H("xyz" + "password123") = 2d8e1c...
```

**Impact on rainbow tables:**
- Without salt: attacker needs ONE table for all users
- With 16-byte salt: attacker would need 2¹²⁸ separate tables — computationally impossible

### 3.3 Salt Properties in Our Implementation

| Algorithm | Salt Length | Salt Storage | Auto-generated |
|-----------|-----------|--------------|----------------|
| SHA-256   | None      | N/A          | No             |
| bcrypt    | 22 bytes  | Embedded in hash string | Yes |
| Argon2id  | 16 bytes  | Embedded in hash string | Yes |

Both bcrypt and Argon2 automatically generate and embed the salt, requiring no extra database columns.

---

## 4. Key Stretching: Making Hashing Intentionally Slow

### 4.1 What is Key Stretching?

Key stretching is the practice of making a hash function **intentionally slow** by applying it multiple times or requiring significant computational resources. This converts the hash function from a general-purpose tool into a password-specific one.

**Purpose:** A legitimate server verifying one password per login can tolerate a 300ms hash computation. An attacker trying billions of passwords cannot.

### 4.2 Cost Factor / Work Factor

Both bcrypt and Argon2 have tunable parameters that control their computational cost:

- **bcrypt:** `cost` parameter (rounds = 2^cost). Default is 12, meaning 2¹² = 4,096 iterations of the Blowfish cipher.
- **Argon2:** Three parameters:
  - `time_cost`: number of iterations (default: 2)
  - `memory_cost`: RAM required in KB (default: 65,536 = 64MB)
  - `parallelism`: number of threads (default: 1)

### 4.3 Impact on Attackers

| Metric | SHA-256 | bcrypt (cost=8) | Argon2id (64MB) |
|--------|---------|-----------------|-----------------|
| Hashes/second (CPU) | ~10,000,000 | ~40 | ~10 |
| Hashes/second (GPU) | ~10,000,000,000 | ~50,000 | Limited by VRAM |
| Time to crack 8-char password | ~37 minutes | ~9 months | Years |

---

## 5. How bcrypt Improves Password Security

### 5.1 bcrypt Overview

bcrypt was designed in 1999 by Niels Provos and David Mazières specifically for password hashing. It is based on the **Blowfish cipher** and incorporates:

- **Automatic salt generation** (22-byte random salt)
- **Configurable cost factor** (work doubles with each increment)
- **Deliberately slow computation** via expensive key setup

### 5.2 bcrypt Hash Format

```
$2b$12$LJ3m4ys3Gl.kUGCAdQ1PoOmGf/oJJVLBhGtLvVT.PIyf/MmhE8D06
 ││  ││ └─────────────────────┘└────────────────────────────────┘
 ││  ││     22-char salt              31-char hash
 ││  └┘
 ││  cost factor (2^12 = 4096 rounds)
 └┘
 algorithm identifier ($2b$ = bcrypt)
```

### 5.3 Why bcrypt is Secure

1. **Salt prevents rainbow tables:** Every hash is unique
2. **Cost factor prevents brute-force:** Each guess takes ~100-500ms
3. **Adaptive:** Cost can be increased as hardware gets faster
4. **Battle-tested:** Used for 25+ years with no practical attacks

### 5.4 Reference

> Provos, N., & Mazières, D. (1999). *A Future-Adaptable Password Scheme.* Proceedings of the USENIX Annual Technical Conference.
> Available: https://www.openbsd.org/papers/bcrypt-paper.pdf

---

## 6. How Argon2 Improves Password Security

### 6.1 Argon2 Overview

Argon2 was designed in 2015 by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich. It won the **Password Hashing Competition (PHC)** and represents the current state of the art.

Argon2 comes in three variants:
- **Argon2d:** Data-dependent memory access (resistant to GPU attacks)
- **Argon2i:** Data-independent memory access (resistant to side-channel attacks)
- **Argon2id:** Hybrid of both (recommended for password hashing)

### 6.2 Memory-Hardness: The Key Innovation

The critical advantage of Argon2 over bcrypt is **memory-hardness**:

- bcrypt is **CPU-hard** — it requires many CPU cycles but minimal RAM
- Argon2 is **memory-hard** — it requires a large amount of RAM (default: 64MB per hash)

**Why this matters for GPU attacks:**

A modern GPU has thousands of cores but limited memory per core. If each hash requires 64MB of RAM:
- A GPU with 8GB VRAM can only run ~125 parallel Argon2 computations
- The same GPU can run thousands of parallel bcrypt computations
- SHA-256 can run billions of parallel computations on a GPU

This dramatically reduces the attacker's advantage when using specialized hardware.

### 6.3 Argon2 Parameters

| Parameter | Our Setting | Purpose |
|-----------|-------------|---------|
| time_cost | 2 | Number of passes over memory |
| memory_cost | 65536 (64MB) | RAM required per hash |
| parallelism | 1 | Threads used |
| hash_len | 32 | Output hash length |
| salt_len | 16 | Random salt length |

### 6.4 Argon2 Hash Format

```
$argon2id$v=19$m=65536,t=2,p=1$<16-byte-salt>$<32-byte-hash>
 │         │    │       │   │
 │         │    │       │   └── parallelism
 │         │    │       └────── time cost (iterations)
 │         │    └────────────── memory cost (KB)
 │         └─────────────────── version
 └───────────────────────────── algorithm (argon2id)
```

### 6.5 Reference

> Biryukov, A., Dinu, D., & Khovratovich, D. (2016). *Argon2: the memory-hard function for password hashing and other applications.* University of Luxembourg.
> Available: https://www.cryptolux.org/images/0/0d/Argon2.pdf

---

## 7. Security Trade-offs Between Algorithms

### 7.1 Comparison Table

| Feature | SHA-256 | bcrypt | Argon2id |
|---------|---------|--------|----------|
| **Year** | 2001 | 1999 | 2015 |
| **Purpose** | General-purpose hashing | Password hashing | Password hashing |
| **Salt** | None (manual) | Automatic (22B) | Automatic (16B) |
| **Key Stretching** | None | CPU-bound (2^cost rounds) | CPU + Memory + Threads |
| **Memory Required** | Negligible | ~4 KB | 64 MB+ (configurable) |
| **GPU Resistance** | Very Low | Moderate | Very High |
| **ASIC Resistance** | Very Low | Low-Moderate | High (memory-bound) |
| **Rainbow Table Resistance** | None | Full | Full |
| **Adjustable Difficulty** | No | Yes (cost factor) | Yes (time, memory, parallelism) |
| **Maturity** | 25+ years | 25+ years | 10+ years |
| **OWASP Recommended** | No | Yes | Yes (preferred) |

### 7.2 When to Use Each

- **SHA-256:** NEVER use for password storage. Suitable for data integrity checks, digital signatures, and checksums.
- **bcrypt:** Good choice for existing systems. Well-understood, widely supported, battle-tested.
- **Argon2id:** Best choice for new applications. Superior GPU/ASIC resistance due to memory-hardness.

### 7.3 Performance vs Security Trade-off

There is an inherent trade-off between server performance and security:

- **Higher cost parameters** = more secure but slower login
- **Lower cost parameters** = faster login but easier to crack

**OWASP recommendations (2024):**
- bcrypt: cost factor ≥ 10 (minimum), 12 (recommended)
- Argon2id: memory ≥ 19MB, time ≥ 2, parallelism ≥ 1

The parameters should be tuned so that password verification takes approximately **250ms–1 second** on the production server.

---

## 8. Resistance to GPU-Based Cracking

### 8.1 Why GPUs Are Dangerous

Modern GPUs are designed for massive parallelism — they can perform thousands of independent calculations simultaneously. This makes them devastating for password cracking:

| Hardware | SHA-256 Hashes/sec | bcrypt Hashes/sec | Argon2 Hashes/sec |
|----------|-------------------|-------------------|-------------------|
| CPU (single core) | ~10 million | ~40 | ~10 |
| GPU (RTX 4090) | ~10 billion | ~50,000 | ~125* |

*Limited by GPU VRAM (24GB / 64MB per hash ≈ 375 max parallel, but memory bandwidth is the bottleneck)

### 8.2 How Each Algorithm Resists GPU Attacks

**SHA-256:**
- Trivially parallelizable on GPUs
- No memory requirement — GPU cores can each compute independently
- Cracking tools (Hashcat) achieve billions of attempts per second

**bcrypt:**
- Moderately GPU-resistant due to expensive Blowfish key schedule
- Each computation requires ~4KB of memory (fits in GPU cache)
- Still vulnerable to large GPU clusters

**Argon2id:**
- Highly GPU-resistant due to **memory-hardness**
- Each computation requires 64MB+ of RAM
- GPU VRAM becomes the bottleneck, not compute cores
- Makes GPU/ASIC-based attacks economically unfeasible at scale

### 8.3 The Memory-Hard Advantage

The key insight: **compute power scales cheaply (more cores), but memory does not.**

An attacker can build a machine with 10,000 GPU cores relatively cheaply, but providing each core with 64MB of dedicated fast memory for Argon2 is prohibitively expensive. This is why memory-hardness is the most important advancement in password hashing.

---

## 9. Project Demonstration Summary

### 9.1 Files and Their Purpose

| File | Purpose |
|------|---------|
| `insecure_auth.py` | SHA-256 authentication system (insecure, no salt) |
| `secure_auth.py` | bcrypt authentication system (secure, salted) |
| `secure_auth_argon2.py` | Argon2id authentication system (secure, memory-hard) |
| `attack_sha.py` | Dictionary attack on SHA-256 database |
| `attack_bcrypt.py` | Dictionary attack on bcrypt database |
| `attack_argon2.py` | Dictionary attack on Argon2 database |
| `bruteforce_attack.py` | Brute-force attack on SHA-256 database |
| `bruteforce_bcrypt.py` | Brute-force attack on bcrypt database |
| `bruteforce_argon2.py` | Brute-force attack on Argon2 database |
| `rainbow_demo.py` | Demonstrates rainbow table vulnerability |
| `benchmark.py` | Comprehensive speed and security comparison |
| `test_cases.py` | Formal authentication and security tests |

### 9.2 Key Observations from Testing

1. **SHA-256 dictionary attack** completes in < 0.001 seconds
2. **bcrypt dictionary attack** takes several seconds (1000x+ slower)
3. **Argon2 dictionary attack** takes even longer (memory allocation overhead)
4. **Same password** produces identical SHA-256 hashes but unique bcrypt/Argon2 hashes
5. **Brute-force** against bcrypt/Argon2 is orders of magnitude slower than against SHA-256

---

## 10. Conclusion

This project demonstrates that **how you store passwords matters more than how complex the passwords are.** Even a strong password is vulnerable if stored with SHA-256, while even a moderate password gains significant protection when stored with bcrypt or Argon2.

**Key takeaways:**
1. **Never use plain SHA-256** (or MD5, SHA-1) for password storage
2. **Always use a unique random salt** per user — prevents rainbow table attacks
3. **Always use key stretching** — makes each guess take hundreds of milliseconds
4. **Argon2id is the best choice** for new applications due to memory-hardness
5. **bcrypt remains a solid choice** for existing systems
6. **Tune cost parameters** to balance server performance with security

---

## References

[1] N. Provos and D. Mazières, *"A Future-Adaptable Password Scheme,"* Proceedings of the USENIX Annual Technical Conference, 1999.
Available: https://www.openbsd.org/papers/bcrypt-paper.pdf

[2] A. Biryukov, D. Dinu, and D. Khovratovich, *"Argon2: the memory-hard function for password hashing and other applications,"* University of Luxembourg, 2016.
Available: https://www.cryptolux.org/images/0/0d/Argon2.pdf

[3] OWASP, *"Password Storage Cheat Sheet,"* 2024.
Available: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

[4] Password Hashing Competition (PHC), https://www.password-hashing.net/

---
