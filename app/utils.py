import base64
import hashlib
import os

from cryptography.fernet import Fernet


def _derive_fernet_key_from_secret(secret: str) -> bytes:
    """Стабильный URL-safe ключ Fernet (32 байта) из секрета приложения."""
    material = hashlib.sha256(f"SecureVault.Fernet.v1|{secret}".encode()).digest()
    return base64.urlsafe_b64encode(material)


class EncryptionManager:
    """Шифрование полей учётных записей (Fernet).

    Порядок ключа:
    1) переменная окружения ENCRYPTION_KEY — готовая строка от Fernet.generate_key().decode();
    2) иначе ключ выводится из SECRET_KEY (или дефолта из config), одинаковый между перезапусками.
    """

    def __init__(self, key=None):
        if key is None:
            key = os.environ.get("ENCRYPTION_KEY")
            if not key:
                secret = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"
                key = _derive_fernet_key_from_secret(secret)

        if isinstance(key, str):
            key = key.strip().encode("ascii")

        self.cipher = Fernet(key)

    @staticmethod
    def generate_key():
        """Генерирует новый ключ шифрования (для .env)."""
        return Fernet.generate_key().decode()

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data).decode()

    def decrypt(self, encrypted_data):
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode("ascii")
        return self.cipher.decrypt(encrypted_data).decode()
