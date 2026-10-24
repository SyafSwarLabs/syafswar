#تشفيروفك التشفير البيانات (AES---DES--GCM)
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SymmetricEngine:
    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(data: bytes, key: bytes):
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return ciphertext, nonce

    @staticmethod
    def decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)