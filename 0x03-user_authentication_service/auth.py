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

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        Uses user's session ID to get the corresponding user
            Args:
                session_id (str/uuid): user's session ID
            Returns:
                the corresponding user's object
        """
        user = self._db.find_user_by(session_id)
        if user is None:
            return
        return user

    def destroy_session(self, user_id: int) -> None:
        """
        Updates corresponding user's session ID to None
            Args:
                user_id (int): user's ID
            Returns:
                None
        """
        self._db.update_user(user_id=user_id, session_id=None)
        return

    def get_reset_password_token(self, email: str) -> str:
        """
        Updates a users reset token
             Returns:
                user's reset token
        """
        user_uuid = str(uuid1())
        user = self._db.find_user_by(email=email)
        if user is None:
            raise ValueError
        self._db.update_user(user_id=user.id, reset_token=user_uuid)
        return user_uuid
