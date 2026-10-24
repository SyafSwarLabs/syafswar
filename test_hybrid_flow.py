import pytest
from core.key_manager import KeyManager
from core.hybrid_engine import HybridEngine

def test_full_hybrid_flow():
    alice_priv, alice_pub = KeyManager.generate_rsa_pair(2048)
    bob_priv, bob_pub = KeyManager.generate_rsa_pair(2048)
    message = "اختبار نظام التشفير الكامل"

    package = HybridEngine.encrypt_package(message, bob_pub, alice_priv)
    result = HybridEngine.decrypt_package(package, bob_priv, alice_pub)
    assert result == message