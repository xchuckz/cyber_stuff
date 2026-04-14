import argon2
import sqlite3

db = sqlite3.connect("users_argon2.db")
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
)
""")
db.commit()

ph = argon2.PasswordHasher(
    time_cost=2,        # number of iterations
    memory_cost=65536,   # 64 MB memory usage
    parallelism=1,       # single thread for demo
    hash_len=32,         # output hash length
    salt_len=16          # salt length
)


def chuck(password):
    return ph.hash(password)


def cosmic(username, password):
    try:
        password_hash = chuck(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        db.commit()
        print(f"[+] User '{username}' registered successfully (SECURE Argon2id).")
    except sqlite3.IntegrityError:
        print("[-] Username already exists.")


def bcy14(username, password):
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if not result:
        print("[-] User not found.")
        return

    stored_hash = result[0]

    try:
        if ph.verify(stored_hash, password):
            print(f"[+] Login successful for '{username}'.")

            # Argon2 supports rehashing if parameters change
            if ph.check_needs_rehash(stored_hash):
                new_hash = chuck(password)
                cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
                db.commit()
                print("[*] Password hash upgraded to new parameters.")
    except argon2.exceptions.VerifyMismatchError:
        print("[-] Incorrect password.")


def show_users():
    cursor.execute("SELECT username, password_hash FROM users")
    rows = cursor.fetchall()

    print("\n--- ARGON2 SECURE DATABASE CONTENTS ---")
    for row in rows:
        print(f"Username: {row[0]} | Hash: {row[1]}")
    print("---------------------------------------\n")


while True:
    print("=== SECURE AUTH SYSTEM (Argon2id) ===")
    print("1. Register")
    print("2. Login")
    print("3. Show Stored Users")
    print("4. Exit")

    choice = input("Enter choice: ")

    if choice == "1":
        user = input("Enter username: ")
        pwd = input("Enter password: ")
        cosmic(user, pwd)

    elif choice == "2":
        user = input("Enter username: ")
        pwd = input("Enter password: ")
        bcy14(user, pwd)

    elif choice == "3":
        show_users()

    elif choice == "4":
        print("Exiting Argon2 auth system.")
        break

    else:
        print("Invalid choice.\n")
