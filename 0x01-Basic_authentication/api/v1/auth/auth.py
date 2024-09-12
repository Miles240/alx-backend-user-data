#!/usr/bin/env python3

"""Auth Module"""

from dataclasses import dataclass


@dataclass
class Auth:
    """Handles user Authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        if path is None or excluded_paths is None:
            return True
        if path in excluded_paths:
            return False

    def authorization_header() -> str:
        pass