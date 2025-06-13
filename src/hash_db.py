"""
hash_db.py - Simple password hash database for Vesper

Stores and retrieves password hashes and salts for verification.
Uses SQLite for demonstration purposes.
"""
import sqlite3
from typing import Optional

DB_PATH = "hashes.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS password_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            salt TEXT,
            hash TEXT,
            algo TEXT DEFAULT 'sha256'
        )
    """)
    conn.commit()
    conn.close()

def store_hash(username: str, salt: str, hash_: str, algo: str = 'sha256') -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO password_hashes (username, salt, hash, algo) VALUES (?, ?, ?, ?)", (username, salt, hash_, algo))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def get_hash(username: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, hash, algo FROM password_hashes WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {'salt': row[0], 'hash': row[1], 'algo': row[2]}
    return None

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
