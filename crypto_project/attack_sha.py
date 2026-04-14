import sqlite3
import hashlib
import time

start = time.time()

db = sqlite3.connect("users_insecure.db")
cursor = db.cursor()

cursor.execute("SELECT username, password_hash FROM users")
users = cursor.fetchall()


def chuck(password):
    return hashlib.sha256(password.encode()).hexdigest()


with open("common_passwords.txt", "r") as file:
    wordlist = [line.strip() for line in file.readlines()]

print("\n=== OFFLINE ATTACK ON INSECURE SHA-256 DATABASE ===\n")

cracked = 0

for username, stored_hash in users:
    found = False

    for word in wordlist:
        if chuck(word) == stored_hash:
            print(f"[CRACKED] {username} --> {word}")
            cracked += 1
            found = True
            break

    if not found:
        print(f"[SAFE FOR NOW] {username} --> Not found in dictionary")

end = time.time()

print(f"\nTotal cracked: {cracked}/{len(users)}")
print(f"Time taken: {end - start:.4f} seconds")