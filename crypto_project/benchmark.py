"""
BENCHMARK: SHA-256 vs bcrypt vs Argon2
Compares hashing speed and cracking resistance across all three algorithms.
"""

import hashlib
import bcrypt
import argon2
import time

# ─── Configuration ───
TEST_PASSWORD = "password123"
NUM_HASHES = 10       # number of hashes to generate for averaging
DICTIONARY_SIZE = 12  # size of common_passwords.txt

ph = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16
)


# ─── SHA-256 (insecure) ───
def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_sha256(password, stored_hash):
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash


# ─── bcrypt (secure) ───
def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=8))


def verify_bcrypt(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash)


# ─── Argon2id (secure) ───
def hash_argon2(password):
    return ph.hash(password)


def verify_argon2(password, stored_hash):
    try:
        return ph.verify(stored_hash, password)
    except argon2.exceptions.VerifyMismatchError:
        return False


# ══════════════════════════════════════════════════
#  BENCHMARK 1: Hashing Speed
# ══════════════════════════════════════════════════
def benchmark_hashing():
    print("=" * 60)
    print("  BENCHMARK 1: HASHING SPEED")
    print(f"  Password: '{TEST_PASSWORD}'")
    print("=" * 60)

    results = {}

    # SHA-256 (very fast, so use many iterations)
    sha_iterations = 100000
    start = time.perf_counter()
    for _ in range(sha_iterations):
        hash_sha256(TEST_PASSWORD)
    elapsed = time.perf_counter() - start
    avg = elapsed / sha_iterations
    results["SHA-256"] = avg
    print(f"\n  SHA-256:")
    print(f"    Total time  : {elapsed:.6f} sec")
    print(f"    Avg per hash: {avg:.10f} sec")
    print(f"    Hashes/sec  : {1/avg:,.0f}")

    # bcrypt
    bcrypt_iterations = 10
    start = time.perf_counter()
    for _ in range(bcrypt_iterations):
        hash_bcrypt(TEST_PASSWORD)
    elapsed = time.perf_counter() - start
    avg = elapsed / bcrypt_iterations
    results["bcrypt"] = avg
    print(f"\n  bcrypt (10 rounds):")
    print(f"    Total time  : {elapsed:.6f} sec")
    print(f"    Avg per hash: {avg:.6f} sec")
    print(f"    Hashes/sec  : {1/avg:,.2f}")

    # Argon2
    argon_iterations = 5
    start = time.perf_counter()
    for _ in range(argon_iterations):
        hash_argon2(TEST_PASSWORD)
    elapsed = time.perf_counter() - start
    avg = elapsed / argon_iterations
    results["Argon2id"] = avg
    print(f"\n  Argon2id (64MB, 2 iterations):")
    print(f"    Total time  : {elapsed:.6f} sec")
    print(f"    Avg per hash: {avg:.6f} sec")
    print(f"    Hashes/sec  : {1/avg:,.2f}")

    # Slowdown factor
    sha_speed = results["SHA-256"]
    print(f"\n  ── Slowdown Factors (vs SHA-256) ──")
    print(f"  bcrypt   is {results['bcrypt']/sha_speed:,.0f}x slower than SHA-256")
    print(f"  Argon2id is {results['Argon2id']/sha_speed:,.0f}x slower than SHA-256")

    return results


# ══════════════════════════════════════════════════
#  BENCHMARK 2: Dictionary Attack Simulation
# ══════════════════════════════════════════════════
def benchmark_cracking():
    print("\n" + "=" * 60)
    print("  BENCHMARK 2: DICTIONARY ATTACK SIMULATION")
    print(f"  Target password: '{TEST_PASSWORD}'")
    print("=" * 60)

    with open("common_passwords.txt", "r") as f:
        wordlist = [line.strip() for line in f.readlines()]

    print(f"  Dictionary size: {len(wordlist)} words\n")

    # SHA-256 attack
    stored_sha = hash_sha256(TEST_PASSWORD)
    start = time.time()
    for word in wordlist:
        if verify_sha256(word, stored_sha):
            break
    sha_time = time.time() - start
    print(f"  SHA-256  attack: {sha_time:.6f} sec to find password")

    # bcrypt attack
    stored_bcrypt = hash_bcrypt(TEST_PASSWORD)
    start = time.time()
    for word in wordlist:
        if verify_bcrypt(word, stored_bcrypt):
            break
    bcrypt_time = time.time() - start
    print(f"  bcrypt   attack: {bcrypt_time:.6f} sec to find password")

    # Argon2 attack
    stored_argon = hash_argon2(TEST_PASSWORD)
    start = time.time()
    for word in wordlist:
        if verify_argon2(word, stored_argon):
            break
    argon_time = time.time() - start
    print(f"  Argon2id attack: {argon_time:.6f} sec to find password")

    print(f"\n  ── Attack Slowdown (vs SHA-256) ──")
    if sha_time > 0:
        print(f"  bcrypt   is {bcrypt_time/sha_time:,.0f}x slower to crack than SHA-256")
        print(f"  Argon2id is {argon_time/sha_time:,.0f}x slower to crack than SHA-256")


# ══════════════════════════════════════════════════
#  BENCHMARK 3: Rainbow Table Resistance
# ══════════════════════════════════════════════════
def benchmark_rainbow():
    print("\n" + "=" * 60)
    print("  BENCHMARK 3: RAINBOW TABLE RESISTANCE")
    print("  Same password hashed multiple times")
    print("=" * 60)

    password = "password123"

    print(f"\n  SHA-256 (NO salt):")
    for i in range(3):
        h = hash_sha256(password)
        print(f"    Hash {i+1}: {h}")
    print("    >> ALL IDENTICAL — vulnerable to rainbow tables!")

    print(f"\n  bcrypt (auto-salt):")
    for i in range(3):
        h = hash_bcrypt(password).decode()
        print(f"    Hash {i+1}: {h}")
    print("    >> ALL DIFFERENT — rainbow tables useless!")

    print(f"\n  Argon2id (auto-salt):")
    for i in range(3):
        h = hash_argon2(password)
        print(f"    Hash {i+1}: {h}")
    print("    >> ALL DIFFERENT — rainbow tables useless!")


# ══════════════════════════════════════════════════
#  BENCHMARK 4: Memory Usage Comparison
# ══════════════════════════════════════════════════
def benchmark_properties():
    print("\n" + "=" * 60)
    print("  BENCHMARK 4: ALGORITHM PROPERTIES COMPARISON")
    print("=" * 60)

    print(f"""
  ┌──────────────┬────────────┬───────────────┬──────────────┐
  │  Property    │  SHA-256   │    bcrypt     │   Argon2id   │
  ├──────────────┼────────────┼───────────────┼──────────────┤
  │ Salt         │  None      │  Auto (22B)   │  Auto (16B)  │
  │ Key Stretch  │  None      │  2^cost       │  time+memory │
  │ Memory Hard  │  No        │  No           │  YES (64MB+) │
  │ GPU Resist   │  Very Low  │  Moderate     │  Very High   │
  │ Output Size  │  64 chars  │  60 chars     │  ~97 chars   │
  │ Year         │  2001      │  1999         │  2015        │
  │ Recommended  │  NO        │  Yes          │  YES (best)  │
  └──────────────┴────────────┴───────────────┴──────────────┘
    """)


# ══════════════════════════════════════════════════
#  RUN ALL BENCHMARKS
# ══════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  SHA-256  vs  bcrypt  vs  Argon2id")
    print("  Comprehensive Security Benchmark")
    print("=" * 60)

    benchmark_hashing()
    benchmark_cracking()
    benchmark_rainbow()
    benchmark_properties()

    print("\n" + "=" * 60)
    print("  CONCLUSION")
    print("=" * 60)
    print("""
  SHA-256:  Fast to compute = fast to crack. No salt = rainbow
            table attacks work. NOT suitable for passwords.

  bcrypt:   Intentionally slow (Blowfish-based). Auto-salts.
            Cost factor doubles work with each increment.
            Good choice, widely used for 25+ years.

  Argon2id: Memory-hard (requires 64MB+ RAM per hash).
            Resistant to GPU/ASIC attacks. Winner of the
            Password Hashing Competition (2015).
            BEST choice for new applications.
    """)
    print("=" * 60)
