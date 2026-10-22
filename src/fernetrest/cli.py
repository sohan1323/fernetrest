import os
import sys
import getpass
import argparse
from .core import encrypt_file, decrypt_file

def interactive_menu():
    print("=" * 55)
    print("       fernetrest - Secure File Encryptor / Decryptor       ")
    print("=" * 55)
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
        pwd = getpass.getpass("Enter encryption password: ")
        confirm_pwd = getpass.getpass("Confirm encryption password: ")
        if pwd != confirm_pwd:
            print("[-] Error: Passwords do not match!")
            return
        if not pwd:
            print("[-] Error: Password cannot be empty!")
            return

        print("\n[*] Encrypting file (PBKDF2 with 600,000 iterations)...")
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

def main():
    parser = argparse.ArgumentParser(
        prog="fernetrest",
        description="fernetrest: Secure Data-at-Rest File Encryption using Fernet and PBKDF2.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Encrypt sub-command
    enc_parser = subparsers.add_parser("encrypt", aliases=["enc", "e"], help="Encrypt a file")
    enc_parser.add_argument("file", help="Path to the file to encrypt")
    enc_parser.add_argument("-o", "--output", help="Optional output path for encrypted file", default=None)

    # Decrypt sub-command
    dec_parser = subparsers.add_parser("decrypt", aliases=["dec", "d"], help="Decrypt a file")
    dec_parser.add_argument("file", help="Path to the file to decrypt (.enc)")
    dec_parser.add_argument("-o", "--output", help="Optional output path for decrypted file", default=None)

    # Interactive flag
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive menu")

    args = parser.parse_args()

    # If no command arguments are passed, or -i is passed, launch interactive menu
    if args.interactive or not args.command:
        interactive_menu()
        return

    if not os.path.isfile(args.file):
        print(f"[-] Error: File '{args.file}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if args.command in ("encrypt", "enc", "e"):
        pwd = getpass.getpass("Enter encryption password: ")
        confirm_pwd = getpass.getpass("Confirm encryption password: ")
        if pwd != confirm_pwd:
            print("[-] Error: Passwords do not match!", file=sys.stderr)
            sys.exit(1)
        if not pwd:
            print("[-] Error: Password cannot be empty!", file=sys.stderr)
            sys.exit(1)

        print("[*] Encrypting file...")
        enc_path = encrypt_file(args.file, pwd, args.output)
        print(f"[+] File encrypted successfully: {enc_path}")

    elif args.command in ("decrypt", "dec", "d"):
        pwd = getpass.getpass("Enter decryption password: ")
        print("[*] Decrypting file...")
        try:
            dec_path = decrypt_file(args.file, pwd, args.output)
            print(f"[+] File decrypted successfully: {dec_path}")
        except Exception as e:
            print(f"[-] {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
