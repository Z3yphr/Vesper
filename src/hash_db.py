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
            hash TEXT
        )
    """)
    conn.commit()
    conn.close()

def store_hash(username: str, salt: str, hash_: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO password_hashes (username, salt, hash) VALUES (?, ?, ?)", (username, salt, hash_))
    conn.commit()
    conn.close()

def get_hash(username: str) -> Optional[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, hash FROM password_hashes WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {'salt': row[0], 'hash': row[1]}
    return None

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
