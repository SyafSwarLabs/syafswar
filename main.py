#نقطة بداية
import sys
sys.path.append('.')

from core.key_manager import KeyManager
from core.hybrid_engine import HybridEngine
from utils.logger import logger

def main():
    logger.info("توليد مفاتيح RSA للمرسل والمستقبل...")
    alice_priv, alice_pub = KeyManager.generate_rsa_pair(2048)
    bob_priv, bob_pub = KeyManager.generate_rsa_pair(2048)

    secret_message = "هذه رسالة سرية للغاية يتم تشفيرها باستخدام نظام التشفير الهجين المتقدم!"
    logger.info(f"الرسالة الأصلية: {secret_message}")

    encrypted_package = HybridEngine.encrypt_package(
        plaintext=secret_message,
        recipient_pub_key=bob_pub,
        sender_priv_key=alice_priv
    )
    logger.info("تم التشفير والتوقيع بنجاح!")
    print("\n--- الحزمة المشفّرة (JSON Payload) ---\n", encrypted_package, "\n")

    decrypted_message = HybridEngine.decrypt_package(
        package_json=encrypted_package,
        recipient_priv_key=bob_priv,
        sender_pub_key=alice_pub
    )
    logger.info(f"الرسالة بعد فك التشفير: {decrypted_message}")

if __name__ == "__main__":
    main()