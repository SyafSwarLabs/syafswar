import pytest
from core.key_manager import KeyManager
from core.asymmetric import AsymmetricEngine

def test_rsa_key_exchange():
    priv, pub = KeyManager.generate_rsa_pair(2048)
    session_key = b"0123456789abcdef0123456789abcdef"
    encrypted_key = AsymmetricEngine.encrypt_key(session_key, pub)
    decrypted_key = AsymmetricEngine.decrypt_key(encrypted_key, priv)
    assert decrypted_key == session_key