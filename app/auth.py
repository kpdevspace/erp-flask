import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import request, jsonify
from flask_login import current_user

from . import db
from .models import User, TokenBlocklist, RefreshToken


def _jwt_secret():
    return os.getenv("JWT_SECRET_KEY") or os.getenv("SECRET_KEY", "dev-secret")


def _now():
    return datetime.now(timezone.utc)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_access_token(user: User, expires_minutes: int = 60) -> str:
    now = _now()
    payload = {
        "jti": secrets.token_hex(16),
        "typ": "access",
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def issue_refresh_token(user: User, expires_days: int = 7) -> str:
    now = _now()
    payload = {
        "jti": secrets.token_hex(16),
        "typ": "refresh",
        "sub": str(user.id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=expires_days)).timestamp()),
    }
    token = jwt.encode(payload, _jwt_secret(), algorithm="HS256")

    row = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(token),
        expires_at=now + timedelta(days=expires_days),
        is_revoked=False,
    )
    db.session.add(row)
    db.session.commit()
    return token


def decode_token(token: str):
    return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])


def revoke_jti(jti: str, token_type: str, exp_epoch: int):
    expires_at = datetime.fromtimestamp(exp_epoch, tz=timezone.utc)
    exists = TokenBlocklist.query.filter_by(jti=jti).first()
    if not exists:
        db.session.add(TokenBlocklist(jti=jti, token_type=token_type, expires_at=expires_at))
        db.session.commit()


def is_revoked(payload: dict) -> bool:
    jti = payload.get("jti")
    if not jti:
        return True
    return TokenBlocklist.query.filter_by(jti=jti).first() is not None


def _from_bearer():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        payload = decode_token(token)
        if payload.get("typ") != "access" or is_revoked(payload):
            return None
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
