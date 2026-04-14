import bcrypt
import sqlite3

db = sqlite3.connect("users_secure.db")
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash BLOB NOT NULL
)
""")
db.commit()


def chuck(password):
    salt = bcrypt.gensalt(rounds=8)   # use 8 for demo
    return bcrypt.hashpw(password.encode(), salt)


def cosmic(username, password):
    try:
        password_hash = chuck(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        db.commit()
        print(f"[+] User '{username}' registered successfully (SECURE bcrypt).")
    except sqlite3.IntegrityError:
        print("[-] Username already exists.")


def bcy14(username, password):
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if not result:
        print("[-] User not found.")
        return

    stored_hash = result[0]

    if bcrypt.checkpw(password.encode(), stored_hash):
        print(f"[+] Login successful for '{username}'.")
    else:
        print("[-] Incorrect password.")


def show_users():
    cursor.execute("SELECT username, password_hash FROM users")
    rows = cursor.fetchall()

    print("\n--- SECURE DATABASE CONTENTS ---")
    for row in rows:
        print(f"Username: {row[0]} | Hash: {row[1].decode()}")
    print("--------------------------------\n")


while True:
    print("=== SECURE AUTH SYSTEM (bcrypt) ===")
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
        print("Exiting secure auth system.")
        break

    else:
        print("Invalid choice.\n")