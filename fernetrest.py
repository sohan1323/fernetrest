import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import getpass


def derive_key(password: str, salt: bytes) -> bytes:
    '''
        Derives a 32-byte url-safe base64-encoded fernet key from a user passwors and a random salt using PBKDF2-HMAC-SHA256
    '''

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )

    # derive 32 raw bytes and base64-encode them for fernet

    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


SALT_SIZE = 16  # 16 bytes - 128 bits

def encrypt_file(file_path: str, password: str) -> str:
    """
    Encrypts any file using password-derived fernet key
    prepends the 16-byte salt to the output file
    """

    # 1.generate new cryptographically random 16-byte salt
    salt = os.urandom(SALT_SIZE)

    # 2.derive 32-byte fernet key from password + salt
    key = derive_key(password,salt)
    fernet = Fernet(key)

    # 3.read the original file in binary mode ('rb')
    with open(file_path,"rb") as f:
        file_data = f.read()

    # 4.encrypt the file data
    encrypted_data = fernet.encrypt(file_data)

    # 5. write [salt] + [Encrypted data] to the new file
    output_path = file_path + ".enc"
    with open(output_path,"wb") as f:
        f.write(salt + encrypted_data)

    return output_path


def decrypt_file(file_path: str, password: str, output_path: str = None) -> str:
    """
        Decrypts a .enc file by extracting salt from the first 16 bytes,
        re-deriving the fernet key and decrypting the cipher text
    """

    # 1. read all bytes from encrypted file
    with open(file_path,"rb") as f:
        file_content = f.read()

    # 2. basic validation - ensure file is at least large enough to contain the salt
    if len(file_content) < SALT_SIZE:
        raise ValueError("File is too small or corrupted to be a valid encrypted file.")

    # 3. Extract the salt (first 16 bytes) and ciphertext (the rest)
    salt = file_content[:SALT_SIZE]
    ciphertext = file_content[SALT_SIZE:]

    # 4. re-derive the key using the extracted salt and provided password
    key = derive_key(password, salt)
    fernet = Fernet(key)

    # 5. Decrypt the ciphertext and handle wrong password or file tampering
    try:
        decrypted_data = fernet.decrypt(ciphertext)
    except InvalidToken:
        raise ValueError("Decryption failed! Incorrect password or corrupted/tampered file.")

    # 6. determine output file path (e.g., test.txt.enc -> test.txt)
    if not output_path:
        if file_path.endswith(".enc"):
            output_path = file_path[:-4] # remove .enc extension
        else:
            output_path = file_path + ".decrypted"
    
    # 7. write the decrypted original bytes to disk
    with open(output_path,"wb") as f:
        f.write(decrypted_data)

    return output_path



def main():
    print("=" * 50)
    print("       SYMMETRIC FILE ENCRYPTOR / DECRYPTOR       ")
    print("=" * 50)
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Exit")
    
    choice = input("\nSelect an option (1-3): ").strip()
    
    if choice == "3":
        print("Goodbye!")
        return
    if choice not in ("1", "2"):
        print("[-] Invalid choice. Exiting.")
        return
    file_path = input("Enter path to the file: ").strip().strip('"')
    if not os.path.isfile(file_path):
        print(f"[-] Error: File '{file_path}' does not exist.")
        return
    if choice == "1":
        # Ask for password twice to prevent accidental typos
        pwd = getpass.getpass("Enter encryption password: ")
        confirm_pwd = getpass.getpass("Confirm encryption password: ")
        if pwd != confirm_pwd:
            print("[-] Error: Passwords do not match!")
            return
        if not pwd:
            print("[-] Error: Password cannot be empty!")
            return
        print("\n[*] Encrypting file (deriving key via PBKDF2 with 600,000 iterations)...")
        enc_file = encrypt_file(file_path, pwd)
        print(f"[+] File encrypted successfully: {enc_file}")
    elif choice == "2":
        pwd = getpass.getpass("Enter decryption password: ")
        print("\n[*] Decrypting file...")
        try:
            dec_file = decrypt_file(file_path, pwd)
            print(f"[+] File decrypted successfully: {dec_file}")
        except Exception as e:
            print(f"[-] {e}")
if __name__ == "__main__":
    main()
