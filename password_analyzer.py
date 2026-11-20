import math
import re
import secrets
import sqlite3
import string

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "111111", "1234567890", "abc123"
}

def calculate_entropy(password: str) -> float:
    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'[0-9]', password):
        pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool_size += 32
    if pool_size == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool_size)

def is_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS

def evaluate_password_strength(password: str) -> dict:
    if is_common_password(password):
        return {
            "strength": "Weak",
            "entropy": calculate_entropy(password),
            "common": True,
            "message": "Password is a common dictionary password."
        }
    entropy = calculate_entropy(password)
    if entropy < 40:
        strength = "Very Weak"
    elif entropy < 60:
        strength = "Weak"
    elif entropy < 80:
        strength = "Moderate"
    else:
        strength = "Strong"
    return {
        "strength": strength,
        "entropy": round(entropy, 2),
        "common": False,
        "message": f"Password strength evaluated as {strength}."
    }

def check_used_password_sqlite(db_path: str, password_hash: str) -> bool:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS used_passwords (hash TEXT PRIMARY KEY)")
    cursor.execute("SELECT 1 FROM used_passwords WHERE hash = ?", (password_hash,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    test_pwd = "P@ssw0rd12345!#Strong"
    print("Evaluation:", evaluate_password_strength(test_pwd))
    print("Generated:", generate_strong_password())
