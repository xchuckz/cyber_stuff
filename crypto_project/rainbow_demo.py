import hashlib

passwords = ["password123", "qwerty", "hello123", "password123","lols123"]


def chuck(password):
    return hashlib.sha256(password.encode()).hexdigest()


print("=== RAINBOW TABLE / UNSALTED HASH DEMO ===\n")

for pwd in passwords:
    print(f"Password: {pwd} --> SHA-256: {chuck(pwd)}")

print("\nObservation:")
print("If two users use the same password, they get the SAME hash when no salt is used.")
print("This allows attackers to use precomputed rainbow tables.")