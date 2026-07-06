"""
Encryption Manager Module
Handles AES encryption/decryption using Fernet (AES-128-CBC with HMAC).
Fernet automatically manages IV generation and prepends it to each token.
"""

import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import KEY_FILE, KEY_ENCODING


class CryptoManager:
    """
    Manages symmetric encryption for the chat application.

    Features:
    - Automatic key generation and persistence
    - AES-128-CBC encryption via Fernet
    - Automatic IV handling (Fernet generates unique IV per message)
    - Password-based key derivation support
    """

    def __init__(self, key_path: Path = KEY_FILE):
        self.key_path = key_path
        self._fernet = None
        self._load_or_generate_key()

    def _load_or_generate_key(self) -> None:
        """Load existing key or generate a new one."""
        if self.key_path.exists():
            with open(self.key_path, "rb") as f:
                key = f.read()
            print(f" Loaded existing encryption key from {self.key_path}")
        else:
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as f:
                f.write(key)
            os.chmod(self.key_path, 0o600)  # Restrict permissions
            print(f" Generated new encryption key at {self.key_path}")
            print(f"     Keep this file secure! Share it with clients to enable decryption.")

        self._fernet = Fernet(key)

    def derive_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """
        Derive a Fernet-compatible key from a password using PBKDF2.
        Useful for password-protected key sharing.
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt a string message.
        Fernet automatically generates a unique IV for each encryption call.
        """
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext must be a string")
        return self._fernet.encrypt(plaintext.encode(KEY_ENCODING))

    def decrypt(self, ciphertext: bytes) -> str:
        """
        Decrypt ciphertext back to string.
        Raises InvalidToken if decryption fails (wrong key or tampered data).
        """
        try:
            decrypted = self._fernet.decrypt(ciphertext)
            return decrypted.decode(KEY_ENCODING)
        except InvalidToken:
            raise ValueError("Decryption failed: Invalid token or wrong key")

    def get_key_string(self) -> str:
        """Return the current key as a base64 string for sharing."""
        with open(self.key_path, "rb") as f:
            return f.read().decode(KEY_ENCODING)


# Singleton instance
_crypto_instance = None

def get_crypto_manager() -> CryptoManager:
    """Get or create the singleton CryptoManager instance."""
    global _crypto_instance
    if _crypto_instance is None:
        _crypto_instance = CryptoManager()
    return _crypto_instance