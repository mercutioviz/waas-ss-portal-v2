"""
Encryption utilities for sensitive data storage
Uses Fernet symmetric encryption with key derived from SECRET_KEY
"""
from cryptography.fernet import Fernet
from flask import current_app
import base64
import hashlib
import json


def get_encryption_key():
    """Derive encryption key from Flask SECRET_KEY"""
    secret = current_app.config['SECRET_KEY'].encode()
    key = hashlib.sha256(secret).digest()
    return base64.urlsafe_b64encode(key)


def encrypt_value(value):
    """Encrypt a string value"""
    if not value:
        return None
    f = Fernet(get_encryption_key())
    return f.encrypt(value.encode()).decode()


def decrypt_value(encrypted_value):
    """Decrypt a string value"""
    if not encrypted_value:
        return None
    f = Fernet(get_encryption_key())
    return f.decrypt(encrypted_value.encode()).decode()


def encrypt_json(data):
    """Encrypt a dictionary as JSON"""
    if not data:
        return None
    json_str = json.dumps(data)
    return encrypt_value(json_str)


def decrypt_json(encrypted_json):
    """Decrypt JSON back to dictionary"""
    if not encrypted_json:
        return {}
    json_str = decrypt_value(encrypted_json)
    return json.loads(json_str)