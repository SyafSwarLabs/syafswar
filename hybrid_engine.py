from core.symmetric import SymmetricEngine
from core.asymmetric import AsymmetricEngine
from integrity.hmac_signatures import SignatureEngine
from utils.serializers import to_base64, from_base64, serialize_payload, deserialize_payload
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class HybridEngine:
    @staticmethod
    def encrypt_package(plaintext: str, recipient_pub_key: RSAPublicKey, sender_priv_key: RSAPrivateKey) -> str:
        data_bytes = plaintext.encode('utf-8')
        session_key = SymmetricEngine.generate_key()
        ciphertext, nonce = SymmetricEngine.encrypt(data_bytes, session_key)
        encrypted_session_key = AsymmetricEngine.encrypt_key(session_key, recipient_pub_key)
        signature = SignatureEngine.sign(ciphertext, sender_priv_key)

        payload = {
            "ciphertext": to_base64(ciphertext),
            "nonce": to_base64(nonce),
            "encrypted_session_key": to_base64(encrypted_session_key),
            "signature": to_base64(signature)
        }
        return serialize_payload(payload)

    @staticmethod
    def decrypt_package(package_json: str, recipient_priv_key: RSAPrivateKey, sender_pub_key: RSAPublicKey) -> str:
        payload = deserialize_payload(package_json)
        ciphertext = from_base64(payload["ciphertext"])
        nonce = from_base64(payload["nonce"])
        encrypted_session_key = from_base64(payload["encrypted_session_key"])
        signature = from_base64(payload["signature"])

        if not SignatureEngine.verify(ciphertext, signature, sender_pub_key):
            raise ValueError("فشل التحقق من التوقيع الرقمي! البيانات متلاعب بها أو المصدر غير موثوق.")

        session_key = AsymmetricEngine.decrypt_key(encrypted_session_key, recipient_priv_key)
        decrypted_bytes = SymmetricEngine.decrypt(ciphertext, nonce, session_key)
        return decrypted_bytes.decode('utf-8')