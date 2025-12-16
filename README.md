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
## Configurable Security Parameters

The IDS allows adjusting key derivation and AES encryption parameters:

```yaml
crypto:
  key_derivation:
    iterations: 200_000
    salt_size: 16
  aes:
    mode: GCM
    key_size: 32
```
## Threat Model

### Assets
- Confidentiality of stored files
- Integrity of encrypted data
- Password-derived encryption keys

### Attacker Capabilities
- Can read encrypted files
- Can modify encrypted files
- Cannot access user password

### Out of Scope
- Compromised endpoint
- Weak user passwords
- Side-channel attacks

## Security Design

- AES-256-GCM is used for authenticated encryption
- PBKDF2 with configurable iterations protects against brute-force attacks
- Random salt prevents precomputed attacks
- HMAC provides defense-in-depth integrity verification

## Failure Modes

- Wrong password → decryption fails
- Tampered file → HMAC verification fails
- Modified nonce or tag → AES-GCM authentication fails
