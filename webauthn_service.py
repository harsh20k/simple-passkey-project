"""
WebAuthn service layer - handles all passkey registration and authentication logic
"""
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import (
    parse_registration_credential_json,
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import secrets
import json


class WebAuthnService:
    """Service class for handling WebAuthn operations"""
    
    def __init__(self, rp_id, rp_name, origin):
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        
        # In-memory storage (replace with database in production)
        self.users_db = {}
        self.credentials_db = {}
    
    def create_user(self, username):
        """Create a new user or return existing user"""
        if username not in self.users_db:
            user_id = secrets.token_bytes(32)
            self.users_db[username] = {
                'id': user_id,
                'username': username,
                'credentials': []
            }
        return self.users_db[username]
    
    def get_user(self, username):
        """Retrieve a user by username"""
        return self.users_db.get(username)
    
    def generate_registration_options(self, username):
        """Generate registration options for a new passkey"""
        user = self.create_user(username)
        
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user['id'],
            user_name=username,
            user_display_name=username,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )
        
        return options, options.challenge.hex()
    
    def verify_registration(self, credential_json, challenge_hex, username):
        """Verify and store a registration credential"""
        challenge_bytes = bytes.fromhex(challenge_hex)
        
        # Parse the credential from JSON
        credential = parse_registration_credential_json(credential_json)
        
        # Verify the registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge_bytes,
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
        )
        
        # Store the credential
        credential_id = verification.credential_id.hex()
        self.credentials_db[credential_id] = {
            'credential_id': verification.credential_id,
            'public_key': verification.credential_public_key,
            'sign_count': verification.sign_count,
            'username': username,
        }
        
        # Associate credential with user
        self.users_db[username]['credentials'].append(credential_id)
        
        return True, f'Passkey registered successfully for {username}!'
    
    def generate_authentication_options(self, username):
        """Generate authentication options for login"""
        user = self.get_user(username)
        if not user:
            raise ValueError('User not found')
        
        # FIXED: Get user's credentials as PublicKeyCredentialDescriptor objects
        user_credentials = [
            PublicKeyCredentialDescriptor(id=self.credentials_db[cred_id]['credential_id'])
            for cred_id in user['credentials']
        ]
        
        if not user_credentials:
            raise ValueError('No passkeys registered for this user')
        
        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=user_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        return options, options.challenge.hex()
    
    def verify_authentication(self, credential_json, challenge_hex):
        """Verify an authentication credential"""
        challenge_bytes = bytes.fromhex(challenge_hex)
        
        # Parse the credential from JSON
        credential = parse_authentication_credential_json(credential_json)
        
        # Find the stored credential
        credential_id = credential.raw_id.hex()
        if credential_id not in self.credentials_db:
            raise ValueError('Credential not found')
        
        stored_credential = self.credentials_db[credential_id]
        
        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_bytes,
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
            credential_public_key=stored_credential['public_key'],
            credential_current_sign_count=stored_credential['sign_count'],
        )
        
        # Update sign count
        self.credentials_db[credential_id]['sign_count'] = verification.new_sign_count
        
        username = stored_credential['username']
        return True, f'Successfully logged in as {username}!', username
