import hashlib
import sqlite3

db = sqlite3.connect("users_insecure.db")
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
)
""")
db.commit()


def chuck(password):
    return hashlib.sha256(password.encode()).hexdigest()


def cosmic(username, password):
    try:
        password_hash = chuck(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        db.commit()
        print(f"[+] User '{username}' registered successfully (INSECURE SHA-256).")
    except sqlite3.IntegrityError:
        print("[-] Username already exists.")


def bcy14(username, password):
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if not result:
        print("[-] User not found.")
        return

    stored_hash = result[0]
    entered_hash = chuck(password)

    if stored_hash == entered_hash:
        print(f"[+] Login successful for '{username}'.")
    else:
        print("[-] Incorrect password.")


def show_users():
    cursor.execute("SELECT username, password_hash FROM users")
    rows = cursor.fetchall()

    print("\n--- INSECURE DATABASE CONTENTS ---")
    for row in rows:
        print(f"Username: {row[0]} | Hash: {row[1]}")
    print("----------------------------------\n")


while True:
    print("=== INSECURE AUTH SYSTEM (SHA-256) ===")
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
        print("Exiting insecure auth system.")
        break

    else:
        print("Invalid choice.\n")