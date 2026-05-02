import hashlib
import os
import secrets
from functools import wraps

from flask import redirect, request, session, url_for

from src.database.db import (
    create_session,
    create_user,
    delete_session,
    get_session,
    get_user_by_username,
    update_user_last_login,
)

ROLE_ADMIN   = 1
ROLE_ANALYST = 2
ROLE_VIEWER  = 3


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, hashed = stored_hash.split(":", 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except Exception:
        return False


def register_user(username: str, email: str, password: str, role_id: int = ROLE_VIEWER) -> bool:
    return create_user(username, email, hash_password(password), role_id)


def login_user(username: str, password: str) -> str | None:
    user = get_user_by_username(username)
    if not user or not user["is_active"]:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    token = secrets.token_hex(32)
    create_session(token, user["id"])
    update_user_last_login(user["id"])
    return token


def logout_user(token: str):
    delete_session(token)


def get_current_user():
    token = session.get("token")
    if not token:
        return None
    sess = get_session(token)
    return sess


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("auth_bp.login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("auth_bp.login"))
            if user["role_id"] not in roles:
                return redirect(url_for("main_bp.dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def init_default_admin():
    from src.database.db import get_user_by_username
    if not get_user_by_username("admin"):
        register_user("admin", "admin@localhost", "admin123", role_id=ROLE_ADMIN)
        register_user("analyst", "analyst@localhost", "analyst123", role_id=ROLE_ANALYST)
        register_user("viewer", "viewer@localhost", "viewer123", role_id=ROLE_VIEWER)
        print("[Auth] Созданы пользователи по умолчанию: admin / analyst / viewer")
