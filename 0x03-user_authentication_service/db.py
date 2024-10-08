#!/usr/bin/env python3
"""DB module
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from user import Base, User
from typing import Optional


class DB:
    """DB class"""

    def __init__(self) -> None:
        """Initialize a new DB instance"""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)  # You don't wanna do this in real life 😂
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object"""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> None:
        """
        Adds a new user to the database
            Args:
                email (str): user's email
                hashed_password (str): user's password, a string for now
            Returns:
                A newly created user object
        """
        new_user = User(email=email, hashed_password=hashed_password)
        session = self._session
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        return new_user

    def find_user_by(self, **kwargs) -> Optional[User]:
        """
        Retrives a user from the database
            Args:
                kwargs (dict): a dictionary of user's details
            Returns:
                user (dict): the first user in the database
        """
        try:
            user = self._session.query(User).filter_by(**kwargs).first()
            if user is None:
                raise NoResultFound
            return user
        except InvalidRequestError:
            return None

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Finds and updates a user
            Args:
                user_id (int): id of the user to be updated
                kwargs (dict): user full details
            Returns:
                None
        """
        user = self.find_user_by(id=user_id)
        new_user = self._session.query(User).filter(User.id == user.id).update(kwargs)
        session = self._session
        session.commit()
