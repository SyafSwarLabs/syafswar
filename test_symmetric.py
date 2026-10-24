import pytest
from core.symmetric import SymmetricEngine

def test_aes_gcm_encryption_decryption():
    key = SymmetricEngine.generate_key()
    data = b"Hello, Security!"
    ciphertext, nonce = SymmetricEngine.encrypt(data, key)
    decrypted = SymmetricEngine.decrypt(ciphertext, nonce, key)
    assert decrypted == data