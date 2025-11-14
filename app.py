from flask import Flask, request, jsonify, send_from_directory
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
import hashlib
import json
from urllib.parse import urlparse

app = Flask(__name__)

def get_rp_id_from_request():
    """Extract rp_id (domain) from the request origin"""
    origin = request.headers.get('Origin') or request.headers.get('Referer', 'http://localhost:5001')
    parsed = urlparse(origin)
    # Extract hostname (domain) without port
    rp_id = parsed.hostname or 'localhost'
    return rp_id

def get_origin_from_request():
    """Get the full origin URL from the request"""
    origin = request.headers.get('Origin') or request.headers.get('Referer', 'http://localhost:5001')
    parsed = urlparse(origin)
    # Reconstruct origin with scheme and hostname (with port if present)
    if parsed.port:
        return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    return f"{parsed.scheme}://{parsed.hostname}"

# In-memory database (replace with real DB in production)
USERS = {}  # {username: {password_hash, credential_id, public_key, sign_count}}

def hash_password(password):
    """Simple password hashing (use bcrypt in production)"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/")
def home():
    return send_from_directory("static", "index.html")

# SIGNUP: Create user account with userid/password
@app.route("/signup", methods=["POST"])
def signup():
    username = request.json.get("username")
    password = request.json.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    if username in USERS:
        return jsonify({"error": "Username already exists"}), 400
    
    # Store user with hashed password
    USERS[username] = {
        "password_hash": hash_password(password),
        "credential_id": None,
        "public_key": None,
        "sign_count": None
    }
    
    return jsonify({"status": "success", "message": "User created successfully"})

# STEP 1: Generate Passkey Registration Options (after signup)
@app.route("/register/passkey/options", methods=["POST"])
def register_passkey_options():
    username = request.json.get("username")
    
    if username not in USERS:
        return jsonify({"error": "User not found"}), 404
    
    # Get rp_id from request origin
    rp_id = get_rp_id_from_request()
    
    # Generate registration options
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="Passkey Demo",
        user_id=username.encode(),
        user_name=username
    )
    
    # Store challenge and rp_id for verification
    USERS[username]["registration_challenge"] = options.challenge
    USERS[username]["registration_rp_id"] = rp_id
    USERS[username]["registration_origin"] = get_origin_from_request()
    
    # Convert options to JSON-serializable format
    # options_to_json returns a JSON string, so parse it first
    options_dict = json.loads(options_to_json(options))
    return jsonify(options_dict)

# STEP 2: Verify Passkey Registration
@app.route("/register/passkey/verify", methods=["POST"])
def register_passkey_verify():
    username = request.json.get("username")
    credential = request.json.get("credential")
    
    if username not in USERS:
        return jsonify({"error": "User not found"}), 404
    
    if "registration_challenge" not in USERS[username]:
        return jsonify({"error": "No registration challenge found"}), 400
    
    expected_challenge = USERS[username]["registration_challenge"]
    expected_rp_id = USERS[username].get("registration_rp_id", "localhost")
    expected_origin = USERS[username].get("registration_origin", "http://localhost:5001")
    
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin
        )
        
        # Store passkey credentials
        USERS[username]["credential_id"] = bytes_to_base64url(verification.credential_id)
        USERS[username]["public_key"] = verification.credential_public_key
        USERS[username]["sign_count"] = verification.sign_count
        
        # Clean up challenge
        del USERS[username]["registration_challenge"]
        
        return jsonify({"status": "success", "message": "Passkey registered successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# STEP 3: Generate Passkey Login Options
@app.route("/login/passkey/options", methods=["POST"])
def login_passkey_options():
    username = request.json.get("username")
    
    if username not in USERS:
        return jsonify({"error": "User not found"}), 404
    
    if not USERS[username].get("credential_id"):
        return jsonify({"error": "No passkey registered for this user"}), 400
    
    # Get rp_id from request origin (should match registration)
    rp_id = USERS[username].get("registration_rp_id", get_rp_id_from_request())
    
    # Create credential descriptor
    credential_descriptor = PublicKeyCredentialDescriptor(
        id=base64url_to_bytes(USERS[username]["credential_id"]),
        type="public-key"
    )
    
    # Generate authentication options
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[credential_descriptor]
    )
    
    # Store challenge and origin for verification
    USERS[username]["auth_challenge"] = options.challenge
    USERS[username]["auth_origin"] = get_origin_from_request()
    
    # Convert options to JSON-serializable format
    # options_to_json returns a JSON string, so parse it first
    options_dict = json.loads(options_to_json(options))
    return jsonify(options_dict)

# STEP 4: Verify Passkey Login
@app.route("/login/passkey/verify", methods=["POST"])
def login_passkey_verify():
    username = request.json.get("username")
    credential = request.json.get("credential")
    
    if username not in USERS:
        return jsonify({"error": "User not found"}), 404
    
    if "auth_challenge" not in USERS[username]:
        return jsonify({"error": "No authentication challenge found"}), 400
    
    if not USERS[username].get("credential_id"):
        return jsonify({"error": "No passkey registered"}), 400
    
    expected_challenge = USERS[username]["auth_challenge"]
    expected_rp_id = USERS[username].get("registration_rp_id", "localhost")
    expected_origin = USERS[username].get("auth_origin", get_origin_from_request())
    
    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=USERS[username]["public_key"],
            credential_current_sign_count=USERS[username]["sign_count"]
        )
        
        # Update sign count to prevent replay attacks
        USERS[username]["sign_count"] = verification.new_sign_count
        
        # Clean up challenge
        del USERS[username]["auth_challenge"]
        
        return jsonify({"status": "success", "message": "Login successful"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)

