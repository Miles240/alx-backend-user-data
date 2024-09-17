#!/usr/bin/env python3
"""auth module"""
import bcrypt
from db import DB
from user import User
from uuid import uuid1


def _hash_password(password: bytes) -> bytes:
    """Hashes a given password"""
    byte = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=byte, salt=salt)
    return hashed_password


def _generate_uuid():
    """Generate a unique id"""
    return str(uuid1())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user
            Args:
                email (str): user's email
                password (str/bytes): user's password
            Returns:
                New user's object
        """
        user = self._db.find_user_by(email=email)
        if user:
            raise ValueError(f"User {email} already exist")
        user_pass = _hash_password(password)
        user = self._db.add_user(email, user_pass)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates a user
            Args:
                email (str): user's email
                password (str): user's password
            Returns:
                True if password is matching else False
        """
        user = self._db.find_user_by(email=email)
        if user:
            if bcrypt.checkpw(password.encode("utf-8"), user.hashed_password):
                return True
            else:
                return False
        return False

    def create_session(self, email: str) -> str:
        """
        finds, generates and stores a user's session id
            Args:
                email (str): user's corresponding email
            Returns:
                user's session id
        """
        user = self._db.find_user_by(email=email)
        if user is None:
            return
        user_uuid = _generate_uuid()
        self._db.update_user(user_id=user.id, session_id=user_uuid)
        return user_uuid
