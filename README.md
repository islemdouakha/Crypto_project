# Secure File Storage

Encrypt files securely with AES-256 and verify integrity with HMAC.

## Features
- AES-256 encryption (GCM)
- Password-based key derivation (PBKDF2)
- HMAC integrity check
- CLI interface: encrypt/decrypt
- Unit-tested

## Usage
```bash
python main.py encrypt secret.txt mypassword
python main.py decrypt secret.txt.enc mypassword
```