import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

SALT_SIZE = 16  # 16 bytes = 128 bits
DEFAULT_ITERATIONS = 600000

def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """
    Derives a 32-byte url-safe base64-encoded Fernet key
    from a user password and a random salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str, output_path: str = None) -> str:
    """
    Encrypts any file using a password-derived Fernet key.
    Prepends the 16-byte salt to the output file (.enc).
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        file_data = f.read()

    encrypted_data = fernet.encrypt(file_data)

    if not output_path:
        output_path = file_path + ".enc"

    with open(output_path, "wb") as f:
        f.write(salt + encrypted_data)

    return output_path

def decrypt_file(file_path: str, password: str, output_path: str = None) -> str:
    """
    Decrypts a .enc file by extracting the salt from the first 16 bytes,
    re-deriving the Fernet key, and decrypting the ciphertext.
    """
    with open(file_path, "rb") as f:
        file_content = f.read()

    if len(file_content) < SALT_SIZE:
        raise ValueError("File is too small or corrupted to be a valid encrypted file.")

    salt = file_content[:SALT_SIZE]
    ciphertext = file_content[SALT_SIZE:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(ciphertext)
    except InvalidToken:
        raise ValueError("Decryption failed! Incorrect password or corrupted/tampered file.")

    if not output_path:
        if file_path.endswith(".enc"):
            output_path = file_path[:-4]
        else:
            output_path = file_path + ".decrypted"

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    return output_path
