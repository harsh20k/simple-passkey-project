"""
Configuration settings for the passkey application
"""
import secrets

class Config:
    """Base configuration"""
    SECRET_KEY = secrets.token_hex(32)
    
    # WebAuthn Configuration
    RP_ID = "localhost"
    RP_NAME = "Passkey Demo App"
    ORIGIN = "http://localhost:5001"
    PORT = 5001
    DEBUG = True
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 600  # 10 minutes
