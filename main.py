import argparse
from crypto import encrypt_file, decrypt_file

def main():
    parser = argparse.ArgumentParser(description="Secure File Storage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("file", help="Path to file to encrypt")
    encrypt_parser.add_argument("password", help="Encryption password")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("file", help="Path to encrypted file")
    decrypt_parser.add_argument("password", help="Decryption password")

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypted_bytes = encrypt_file(args.file, args.password)
        with open(args.file + ".enc", "wb") as f:
            f.write(encrypted_bytes)
        print(f"Encrypted file saved as {args.file}.enc")

    elif args.command == "decrypt":
        with open(args.file, "rb") as f:
            encrypted_bytes = f.read()
        decrypted_bytes = decrypt_file(encrypted_bytes, args.password)
        output_file = args.file.replace(".enc", ".dec")
        with open(output_file, "wb") as f:
            f.write(decrypted_bytes)
        print(f"Decrypted file saved as {output_file}")

        try:
            decrypted_bytes = decrypt_file(encrypted_bytes, args.password)
        except ValueError as e:
            print(f"ERROR: {e}")
            exit(1)


if __name__ == "__main__":
    main()
