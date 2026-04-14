"""
TEST CASES: Secure Password Storage and Authentication System
Demonstrates:
  1. Successful authentication with correct credentials
  2. Failure of authentication with incorrect passwords
  3. Increased resistance to password cracking with salting and key stretching
"""

import hashlib
import bcrypt
import argon2
import sqlite3
import time
import os

ph = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16
)

PASSED = 0
FAILED = 0


def test(name, condition):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [PASS] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}")


# ══════════════════════════════════════════════════════
#  TEST SUITE 1: SHA-256 Authentication
# ══════════════════════════════════════════════════════
def test_sha256_auth():
    print("\n" + "=" * 55)
    print("  TEST SUITE 1: SHA-256 Authentication")
    print("=" * 55)

    db = sqlite3.connect(":memory:")
    cur = db.cursor()
    cur.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")

    def hash_pw(pw):
        return hashlib.sha256(pw.encode()).hexdigest()

    # Register
    pw_hash = hash_pw("mypassword")
    cur.execute("INSERT INTO users VALUES (?, ?)", ("alice", pw_hash))
    db.commit()

    # Test 1: Correct password
    cur.execute("SELECT password_hash FROM users WHERE username = ?", ("alice",))
    stored = cur.fetchone()[0]
    test("SHA-256: Correct password authenticates", hash_pw("mypassword") == stored)

    # Test 2: Wrong password
    test("SHA-256: Wrong password is rejected", hash_pw("wrongpassword") != stored)

    # Test 3: Same password = same hash (no salt)
    hash1 = hash_pw("password123")
    hash2 = hash_pw("password123")
    test("SHA-256: Same password produces identical hash (no salt)", hash1 == hash2)

    # Test 4: Non-existent user
    cur.execute("SELECT password_hash FROM users WHERE username = ?", ("bob",))
    result = cur.fetchone()
    test("SHA-256: Non-existent user returns None", result is None)

    db.close()


# ══════════════════════════════════════════════════════
#  TEST SUITE 2: bcrypt Authentication
# ══════════════════════════════════════════════════════
def test_bcrypt_auth():
    print("\n" + "=" * 55)
    print("  TEST SUITE 2: bcrypt Authentication")
    print("=" * 55)

    db = sqlite3.connect(":memory:")
    cur = db.cursor()
    cur.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash BLOB NOT NULL)")

    # Register
    pw_hash = bcrypt.hashpw("mypassword".encode(), bcrypt.gensalt(rounds=8))
    cur.execute("INSERT INTO users VALUES (?, ?)", ("alice", pw_hash))
    db.commit()

    # Test 1: Correct password
    cur.execute("SELECT password_hash FROM users WHERE username = ?", ("alice",))
    stored = cur.fetchone()[0]
    test("bcrypt: Correct password authenticates", bcrypt.checkpw("mypassword".encode(), stored))

    # Test 2: Wrong password
    test("bcrypt: Wrong password is rejected", not bcrypt.checkpw("wrongpassword".encode(), stored))

    # Test 3: Same password = different hash (salt!)
    hash1 = bcrypt.hashpw("password123".encode(), bcrypt.gensalt(rounds=8))
    hash2 = bcrypt.hashpw("password123".encode(), bcrypt.gensalt(rounds=8))
    test("bcrypt: Same password produces DIFFERENT hashes (salt)", hash1 != hash2)

    # Test 4: Both different hashes still verify correctly
    test("bcrypt: Different hash of same pw still verifies (hash1)", bcrypt.checkpw("password123".encode(), hash1))
    test("bcrypt: Different hash of same pw still verifies (hash2)", bcrypt.checkpw("password123".encode(), hash2))

    # Test 5: Non-existent user
    cur.execute("SELECT password_hash FROM users WHERE username = ?", ("bob",))
    result = cur.fetchone()
    test("bcrypt: Non-existent user returns None", result is None)

    db.close()


# ══════════════════════════════════════════════════════
#  TEST SUITE 3: Argon2 Authentication
# ══════════════════════════════════════════════════════
def test_argon2_auth():
    print("\n" + "=" * 55)
    print("  TEST SUITE 3: Argon2id Authentication")
    print("=" * 55)

    db = sqlite3.connect(":memory:")
    cur = db.cursor()
    cur.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")

    # Register
    pw_hash = ph.hash("mypassword")
    cur.execute("INSERT INTO users VALUES (?, ?)", ("alice", pw_hash))
    db.commit()

    # Test 1: Correct password
    cur.execute("SELECT password_hash FROM users WHERE username = ?", ("alice",))
    stored = cur.fetchone()[0]
    test("Argon2: Correct password authenticates", ph.verify(stored, "mypassword"))

    # Test 2: Wrong password
    try:
        ph.verify(stored, "wrongpassword")
        test("Argon2: Wrong password is rejected", False)
    except argon2.exceptions.VerifyMismatchError:
        test("Argon2: Wrong password is rejected", True)

    # Test 3: Same password = different hash (salt!)
    hash1 = ph.hash("password123")
    hash2 = ph.hash("password123")
    test("Argon2: Same password produces DIFFERENT hashes (salt)", hash1 != hash2)

    # Test 4: Both different hashes still verify
    test("Argon2: Different hash of same pw still verifies (hash1)", ph.verify(hash1, "password123"))
    test("Argon2: Different hash of same pw still verifies (hash2)", ph.verify(hash2, "password123"))

    # Test 5: Non-existent user
    cur.execute("SELECT password_hash FROM users WHERE username = ?", ("bob",))
    result = cur.fetchone()
    test("Argon2: Non-existent user returns None", result is None)

    db.close()


# ══════════════════════════════════════════════════════
#  TEST SUITE 4: Cracking Resistance Comparison
# ══════════════════════════════════════════════════════
def test_cracking_resistance():
    print("\n" + "=" * 55)
    print("  TEST SUITE 4: Cracking Resistance Comparison")
    print("=" * 55)

    target = "password123"
    num_attempts = 10

    # SHA-256 cracking speed
    sha_hash = hashlib.sha256(target.encode()).hexdigest()
    start = time.time()
    for _ in range(num_attempts):
        hashlib.sha256(target.encode()).hexdigest() == sha_hash
    sha_time = (time.time() - start) / num_attempts

    # bcrypt cracking speed
    bcrypt_hash = bcrypt.hashpw(target.encode(), bcrypt.gensalt(rounds=8))
    start = time.time()
    for _ in range(num_attempts):
        bcrypt.checkpw(target.encode(), bcrypt_hash)
    bcrypt_time = (time.time() - start) / num_attempts

    # Argon2 cracking speed
    argon_hash = ph.hash(target)
    start = time.time()
    for _ in range(num_attempts):
        ph.verify(argon_hash, target)
    argon_time = (time.time() - start) / num_attempts

    print(f"\n  Average verification time per attempt:")
    print(f"    SHA-256  : {sha_time*1000:.4f} ms")
    print(f"    bcrypt   : {bcrypt_time*1000:.4f} ms")
    print(f"    Argon2id : {argon_time*1000:.4f} ms\n")

    test("bcrypt is slower than SHA-256 (key stretching works)", bcrypt_time > sha_time)
    test("Argon2 is slower than SHA-256 (key stretching works)", argon_time > sha_time)
    test("bcrypt is at least 100x slower than SHA-256", bcrypt_time > sha_time * 100)
    test("Argon2 is at least 100x slower than SHA-256", argon_time > sha_time * 100)

    if sha_time > 0:
        print(f"\n  Slowdown factors:")
        print(f"    bcrypt   is {bcrypt_time/sha_time:,.0f}x slower than SHA-256")
        print(f"    Argon2id is {argon_time/sha_time:,.0f}x slower than SHA-256")


# ══════════════════════════════════════════════════════
#  RUN ALL TESTS
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("   RUNNING ALL TEST CASES")
    print("   Secure Password Storage & Authentication")
    print("=" * 55)

    test_sha256_auth()
    test_bcrypt_auth()
    test_argon2_auth()
    test_cracking_resistance()

    print("\n" + "=" * 55)
    print(f"   RESULTS: {PASSED} passed, {FAILED} failed, {PASSED + FAILED} total")
    print("=" * 55 + "\n")
