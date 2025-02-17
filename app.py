from flask import Flask, jsonify, request
import jwt
from keys import get_active_keys, get_key_by_kid, get_all_keys
from datetime import datetime, timedelta

app = Flask(__name__)

# JWT configuration
JWT_ISSUER = "jwks-server"
JWT_AUDIENCE = "test-audience"
JWT_EXPIRATION = timedelta(minutes=30)

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serve JWKS including active keys only."""
    return jsonify({"keys": get_active_keys()}), 200

@app.route("/auth", methods=["POST"])
def auth():
    """Issue a JWT signed with an active or expired key depending on the query parameter."""
    expired = request.args.get("expired") == "true"
    
    # Choose the appropriate key based on expired flag
    kid = "expired_key" if expired else "key1"
    
    key_info = get_key_by_kid(kid)
    if not key_info:
        return jsonify({"error": f"Key with kid '{kid}' not found"}), 404

    # Set expiration time
    if expired:
        # For expired token, use a time in the past
        exp_time = datetime.utcnow() - timedelta(days=1)
    else:
        # For valid token, use future time
        exp_time = datetime.utcnow() + JWT_EXPIRATION

    # Create the JWT token with proper headers
    headers = {
        "kid": kid,  # Include the kid in the JWT header
        "alg": "RS256"
    }
    
    payload = {
        "sub": "test_user",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "exp": int(exp_time.timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
    }
    
    # Encode with the private key
    token = jwt.encode(
        payload=payload,
        key=key_info["private_key"], 
        algorithm="RS256",
        headers=headers
    )

    return jsonify({"token": token}), 200

if __name__ == "__main__":
    app.run(port=8080)