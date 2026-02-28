import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import request, jsonify
from flask_login import current_user

from .models import User


def _jwt_secret():
    return os.getenv("JWT_SECRET_KEY") or os.getenv("SECRET_KEY", "dev-secret")


def issue_token(user: User, expires_hours: int = 12) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=expires_hours)).timestamp()),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def _from_bearer():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
        return User.query.get(int(payload.get("sub")))
    except Exception:
        return None


def get_api_user():
    if getattr(current_user, "is_authenticated", False):
        return current_user
    return _from_bearer()


def api_auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_api_user()
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        request.api_user = user
        return fn(*args, **kwargs)

    return wrapper


def api_role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @api_auth_required
        def wrapper(*args, **kwargs):
            user = request.api_user
            if user.role not in roles:
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator
