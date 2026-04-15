import os
import json
from functools import wraps
from urllib.request import urlopen

from flask import request, jsonify
from jose import jwt, JWTError

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
API_AUDIENCE = os.environ.get("API_AUDIENCE", "")
ALGORITHMS = ["RS256"]
NAMESPACE = "https://social-insper.com/"


def get_token_from_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        return None, {"error": "authorization_header_missing", "description": "Authorization header is expected"}, 401

    parts = auth.split()
    if parts[0].lower() != "bearer":
        return None, {"error": "invalid_header", "description": "Authorization header must start with Bearer"}, 401
    if len(parts) == 1:
        return None, {"error": "invalid_header", "description": "Token not found"}, 401
    if len(parts) > 2:
        return None, {"error": "invalid_header", "description": "Authorization header must be Bearer token"}, 401

    return parts[1], None, None


def verify_token(token):
    if not AUTH0_DOMAIN:
        return None, {"error": "server_misconfiguration", "description": "AUTH0_DOMAIN not configured"}, 500

    jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    try:
        jwks = json.loads(urlopen(jwks_url).read())
    except Exception:
        return None, {"error": "jwks_fetch_error", "description": "Could not fetch JWKS"}, 500

    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        return None, {"error": "invalid_header", "description": "Invalid token header"}, 401

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header.get("kid"):
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
            break

    if not rsa_key:
        return None, {"error": "invalid_header", "description": "Unable to find appropriate key"}, 401

    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        return payload, None, None
    except jwt.ExpiredSignatureError:
        return None, {"error": "token_expired", "description": "Token is expired"}, 401
    except jwt.JWTClaimsError:
        return None, {"error": "invalid_claims", "description": "Incorrect claims, check audience and issuer"}, 401
    except JWTError:
        return None, {"error": "invalid_token", "description": "Unable to parse token"}, 401


def require_auth(f):
    """Decorator: requires a valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token, error, status = get_token_from_header()
        if error:
            return jsonify(error), status

        payload, error, status = verify_token(token)
        if error:
            return jsonify(error), status

        request.current_user = payload
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator: requires a valid JWT token with the ADMIN role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token, error, status = get_token_from_header()
        if error:
            return jsonify(error), status

        payload, error, status = verify_token(token)
        if error:
            return jsonify(error), status

        roles = payload.get(f"{NAMESPACE}roles", []) or []
        if "ADMIN" not in roles:
            return jsonify({"error": "forbidden", "description": "Admin role required"}), 403

        request.current_user = payload
        return f(*args, **kwargs)
    return decorated
