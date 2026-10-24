#تشفير وفك التشفير ومفتاح الجلسة (RSA--ECC)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class AsymmetricEngine:
    @staticmethod
    def encrypt_key(session_key: bytes, public_key: RSAPublicKey) -> bytes:
        return public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_key(encrypted_session_key: bytes, private_key: RSAPrivateKey) -> bytes:
        return private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )