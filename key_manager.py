#توليد وقراءة أزواج المفاتيح(public/private--keys)
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class KeyManager:
    @staticmethod
    def generate_rsa_pair(key_size: int = 4096):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key, private_key.public_key()

    @staticmethod
    def save_key_to_file(key, filepath: str, is_private: bool = False):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        if is_private:
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open(filepath, "wb") as f:
            f.write(pem)

    @staticmethod
    def load_private_key(filepath: str):
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    @staticmethod
    def load_public_key(filepath: str):
        with open(filepath, "rb") as f:
            return serialization.load_pem_public_key(f.read())