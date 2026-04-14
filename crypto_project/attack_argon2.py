import sqlite3
import argon2
import time

start = time.time()

db = sqlite3.connect("users_argon2.db")
cursor = db.cursor()

cursor.execute("SELECT username, password_hash FROM users")
users = cursor.fetchall()

ph = argon2.PasswordHasher()

with open("common_passwords.txt", "r") as file:
    wordlist = [line.strip() for line in file.readlines()]

print("\n=== OFFLINE ATTACK ON SECURE Argon2 DATABASE ===\n")

cracked = 0

for username, stored_hash in users:
    found = False

    for word in wordlist:
        try:
            if ph.verify(stored_hash, word):
                print(f"[CRACKED] {username} --> {word}")
                cracked += 1
                found = True
                break
        except argon2.exceptions.VerifyMismatchError:
            continue

    if not found:
        print(f"[SAFE FOR NOW] {username} --> Not found in dictionary")

end = time.time()

print(f"\nTotal cracked: {cracked}/{len(users)}")
print(f"Time taken: {end - start:.4f} seconds")
