import sqlite3
import hashlib
import time
import itertools
import string

chars = string.ascii_lowercase
MAX_LENGTH = 3  # safe for demo

db = sqlite3.connect("users_insecure.db")
cursor = db.cursor()

cursor.execute("SELECT username, password_hash FROM users")
users = cursor.fetchall()


def chuck(password):
    return hashlib.sha256(password.encode()).hexdigest()


print("\n=== BRUTE FORCE ATTACK ON SHA-256 DATABASE ===\n")

start = time.time()
cracked = 0

for username, stored_hash in users:
    found = False
    attempts = 0

    print(f"[ATTACKING] {username}...")

    for length in range(1, MAX_LENGTH + 1):
        for combo in itertools.product(chars, repeat=length):
            guess = ''.join(combo)
            attempts += 1

            if chuck(guess) == stored_hash:
                print(f"[CRACKED] {username} --> {guess} | Attempts: {attempts}")
                cracked += 1
                found = True
                break

        if found:
            break

    if not found:
        print(f"[FAILED] {username} --> Not cracked within {MAX_LENGTH} lowercase letters")

end = time.time()

print(f"\nTotal cracked: {cracked}/{len(users)}")
print(f"Time taken: {end - start:.4f} seconds")