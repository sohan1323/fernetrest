"""
fernetrest: Secure symmetric file encryption and decryption at rest using Fernet and PBKDF2.
"""

from .core import derive_key, encrypt_file, decrypt_file, SALT_SIZE, DEFAULT_ITERATIONS

__version__ = "0.1.0"
__all__ = ["derive_key", "encrypt_file", "decrypt_file", "SALT_SIZE", "DEFAULT_ITERATIONS"]
