#!/usr/bin/env python3
"""auth module"""
import bcrypt
from typing import Optional


def _hash_password(password: bytes) -> bytes:
    """Hashes a given password"""
    byte = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=byte, salt=salt)
    return hashed_password
