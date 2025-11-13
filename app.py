from flask import Flask, request, jsonify, send_from_directory
from webauthn import create_webauthn_credentials, get_webauthn_credentials
from webauthn import verify_create_webauthn_credentials, verify_get_webauthn_credentials
from webauthn.types import RelyingParty, User
from webauthn import metadata
import base64

app = Flask(__name__)

# Temporary in-memory "database"
USERS = {}

# Create a minimal FIDO metadata (required by verify functions)
# In production, you should use proper FIDO metadata from FIDO Alliance
# For now, create an empty metadata object
FIDO_METADATA = metadata.FIDOMetadata(
    entries=[],
    aaguid_map={},
    cki_map={}
)

@app.route("/")
def home():
    return send_from_directory("static", "index.html")

# STEP 1: Generate Registration Options
@app.route("/register/options", methods=["POST"])
def register_options():
    username = request.json["username"]
    
    rp = RelyingParty(id="localhost", name="Passkey Demo")
    user = User(
        id=username.encode()[:64],  # Max 64 bytes
        name=username,
        display_name=username
    )
    
    options_dict, challenge = create_webauthn_credentials(
        rp=rp,
        user=user
    )
    
    USERS[username] = {
        "challenge": challenge,
        "rp": rp
    }
    
    # Wrap in publicKey for the frontend
    return jsonify({"publicKey": options_dict})


# STEP 2: Verify Registration Response (Passkey Created)
@app.route("/register/verify", methods=["POST"])
def register_verify():
    username = request.json["username"]
    credential = request.json["credential"]
    
    if username not in USERS:
        return jsonify({"error": "User not found"}), 400
    
    stored_data = USERS[username]
    challenge = stored_data["challenge"]
    rp = stored_data["rp"]
    
    # Extract data from credential (format from browser)
    # The credential comes as: { id: "...", response: { clientDataJSON: "...", attestationObject: "..." } }
    credential_response = credential.get("response", {})
    client_data_b64 = credential_response.get("clientDataJSON", "")
    attestation_b64 = credential_response.get("attestationObject", "")
    credential_id = credential.get("id", "") or credential.get("rawId", "")
    
    if not client_data_b64 or not attestation_b64:
        return jsonify({"error": "Missing credential data"}), 400
    
    # The data is already base64 encoded from the browser, but we need to ensure proper padding
    # Convert base64url to base64 if needed
    def ensure_base64_padding(s):
        s = s.replace('-', '+').replace('_', '/')
        # Add padding if needed
        pad = len(s) % 4
        if pad:
            s += '=' * (4 - pad)
        return s
    
    client_data_b64 = ensure_base64_padding(client_data_b64)
    attestation_b64 = ensure_base64_padding(attestation_b64)
    
    try:
        verified = verify_create_webauthn_credentials(
            rp=rp,
            challenge_b64=challenge,
            client_data_b64=client_data_b64,
            attestation_b64=attestation_b64,
            fido_metadata=FIDO_METADATA,
            user_verification_required=False
        )
        
        # Store credential info
        # credential_id from browser is already base64url encoded
        USERS[username]["credential_id"] = verified.public_key  # Store public key bytes
        USERS[username]["credential_id_b64"] = credential_id  # Store the credential ID from browser
        USERS[username]["public_key"] = verified.public_key
        USERS[username]["public_key_alg"] = verified.public_key_alg
        USERS[username]["sign_count"] = verified.sign_count
        
        return jsonify({"status": "registered"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# STEP 3: Generate Login Options
@app.route("/login/options", methods=["POST"])
def login_options():
    username = request.json["username"]
    
    if username not in USERS or "credential_id_b64" not in USERS[username]:
        return jsonify({"error": "User not registered"}), 400
    
    rp = RelyingParty(id="localhost", name="Passkey Demo")
    credential_id_b64 = USERS[username]["credential_id_b64"]
    
    # Decode credential ID (it's base64url from browser, convert to base64)
    def base64url_to_bytes(s):
        s = s.replace('-', '+').replace('_', '/')
        pad = len(s) % 4
        if pad:
            s += '=' * (4 - pad)
        return base64.b64decode(s)
    
    credential_id_bytes = base64url_to_bytes(credential_id_b64)
    
    options_dict, challenge = get_webauthn_credentials(
        rp=rp,
        existing_keys=[credential_id_bytes]
    )
    
    USERS[username]["login_challenge"] = challenge
    
    # Wrap in publicKey for the frontend
    return jsonify({"publicKey": options_dict})


# STEP 4: Verify Login Response (Passkey Login)
@app.route("/login/verify", methods=["POST"])
def login_verify():
    username = request.json["username"]
    credential = request.json["credential"]
    
    if username not in USERS:
        return jsonify({"error": "User not found"}), 400
    
    stored_data = USERS[username]
    challenge = stored_data.get("login_challenge")
    
    if not challenge:
        return jsonify({"error": "No login challenge found"}), 400
    
    rp = RelyingParty(id="localhost", name="Passkey Demo")
    
    # Extract data from credential (format from browser)
    credential_response = credential.get("response", {})
    client_data_b64 = credential_response.get("clientDataJSON", "")
    authenticator_data_b64 = credential_response.get("authenticatorData", "")
    signature_b64 = credential_response.get("signature", "")
    
    if not client_data_b64 or not authenticator_data_b64 or not signature_b64:
        return jsonify({"error": "Missing credential data"}), 400
    
    # Convert from base64url to base64 with proper padding
    def ensure_base64_padding(s):
        s = s.replace('-', '+').replace('_', '/')
        pad = len(s) % 4
        if pad:
            s += '=' * (4 - pad)
        return s
    
    client_data_b64 = ensure_base64_padding(client_data_b64)
    authenticator_data_b64 = ensure_base64_padding(authenticator_data_b64)
    signature_b64 = ensure_base64_padding(signature_b64)
    
    try:
        verification = verify_get_webauthn_credentials(
            rp=rp,
            challenge_b64=challenge,
            client_data_b64=client_data_b64,
            authenticator_b64=authenticator_data_b64,
            signature_b64=signature_b64,
            sign_count=stored_data.get("sign_count", 0),
            pubkey_alg=stored_data.get("public_key_alg"),
            pubkey=stored_data.get("public_key"),
            user_verification_required=False
        )
        
        # Update sign count
        USERS[username]["sign_count"] = verification.sign_count
        
        return jsonify({"status": "authenticated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True)
