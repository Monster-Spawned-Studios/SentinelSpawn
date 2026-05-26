#!/usr/bin/env python3
"""
auth.py - Secure authentication with TOTP MFA and encrypted credential storage.
Supports first-login password change and user management.
"""

import sqlite3
import bcrypt
import pyotp
from cryptography.fernet import Fernet
from pathlib import Path
import os
from datetime import datetime
from typing import Optional, Dict, List

DB_PATH = Path("/app/data/users.db")
SECRET_KEY_ENV = "SECRET_KEY"

class AuthManager:
    def __init__(self):
        self.db_path = DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self.secret_key = self._load_secret_key()
        self.sessions = {}
        self.pending_mfa = {}

    def _load_secret_key(self) -> bytes:
        key = os.environ.get(SECRET_KEY_ENV, "").strip()
        if not key:
            raise ValueError(f"{SECRET_KEY_ENV} must be set")
        try:
            Fernet(key.encode())
        except Exception as exc:
            raise ValueError(f"{SECRET_KEY_ENV} is invalid") from exc
        return key.encode()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    totp_secret_encrypted BLOB NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    requires_password_change INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_login TEXT
                )
            """)
            conn.commit()

    def create_first_admin(self, username: str, password: str) -> str:
        """Create the very first admin with TOTP and force password change."""
        if self.has_users():
            raise ValueError("Admin already exists")

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        totp = pyotp.TOTP(pyotp.random_base32())
        totp_secret = totp.secret
        f = Fernet(self.secret_key)
        encrypted_secret = f.encrypt(totp_secret.encode())

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO users 
                (username, password_hash, totp_secret_encrypted, is_admin, requires_password_change)
                VALUES (?, ?, ?, 1, 1)
            """, (username, password_hash, encrypted_secret))
            conn.commit()

        return totp.provisioning_uri(name=username, issuer_name="SentinelSpawn")

    def has_users(self) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            return result > 0

    def has_admin(self) -> bool:
        return self.has_users()

    def create_admin(self, username: str, password: str) -> str:
        return self.create_first_admin(username, password)

    def verify_password(self, username: str, password: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, password_hash, totp_secret_encrypted, requires_password_change FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            if not row:
                return None

            user_id, password_hash, encrypted_secret, requires_change = row

            if not bcrypt.checkpw(password.encode(), password_hash):
                return None

            try:
                Fernet(self.secret_key).decrypt(encrypted_secret)
            except Exception:
                return None

            return {
                "user_id": user_id,
                "username": username,
                "requires_password_change": bool(requires_change),
                "is_admin": True  # For this version we assume single admin
            }

    def verify_totp(self, username: str, totp_code: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, totp_secret_encrypted FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            if not row:
                return False
            user_id, encrypted_secret = row

            try:
                totp_secret = Fernet(self.secret_key).decrypt(encrypted_secret).decode()
                if not pyotp.TOTP(totp_secret).verify(totp_code):
                    return False
            except Exception:
                return False

            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), user_id)
            )
            conn.commit()
            return True

    def verify_login(self, username: str, password: str, totp_code: str) -> Optional[Dict]:
        user = self.verify_password(username, password)
        if not user:
            return None
        if not self.verify_totp(username, totp_code):
            return None
        return user

    def change_password(self, username: str, new_password: str):
        password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, requires_password_change = 0 WHERE username = ?",
                (password_hash, username)
            )
            conn.commit()

    def change_username(self, old_username: str, new_username: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET username = ? WHERE username = ?",
                (new_username, old_username)
            )
            conn.commit()

    def get_user(self, username: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT username, requires_password_change, last_login FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            if row:
                return {
                    "username": row[0],
                    "requires_password_change": bool(row[1]),
                    "last_login": row[2]
                }
        return None

    def list_users(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT username, last_login FROM users").fetchall()
            return [{"username": r[0], "last_login": r[1]} for r in rows]
