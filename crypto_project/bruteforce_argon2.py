import sqlite3
import argon2
import time
import itertools
import string

chars = string.ascii_lowercase
MAX_LENGTH = 3  # brute-force only up to 3 lowercase letters

db = sqlite3.connect("users_argon2.db")
cursor = db.cursor()

cursor.execute("SELECT username, password_hash FROM users")
users = cursor.fetchall()

ph = argon2.PasswordHasher()

print("\n=== BRUTE FORCE ATTACK ON Argon2 DATABASE ===")
print(f"Search Space: lowercase a-z, length 1 to {MAX_LENGTH}\n")

start = time.time()
cracked = 0

for username, stored_hash in users:
    found = False
    attempts = 0
    user_start = time.time()

    print(f"[ATTACKING] {username}...")

    for length in range(1, MAX_LENGTH + 1):
        for combo in itertools.product(chars, repeat=length):
            guess = ''.join(combo)
            attempts += 1

            try:
                if ph.verify(stored_hash, guess):
                    user_end = time.time()
                    print(f"[CRACKED] {username} --> {guess} | Attempts: {attempts} | Time: {user_end - user_start:.4f} sec")
                    cracked += 1
                    found = True
                    break
            except argon2.exceptions.VerifyMismatchError:
                continue

        if found:
            break

    if not found:
        user_end = time.time()
        print(f"[FAILED] {username} --> Password not cracked within {MAX_LENGTH} lowercase letters | Attempts: {attempts} | Time: {user_end - user_start:.4f} sec")

end = time.time()

print(f"\nTotal cracked: {cracked}/{len(users)}")
print(f"Total time taken: {end - start:.4f} seconds")
