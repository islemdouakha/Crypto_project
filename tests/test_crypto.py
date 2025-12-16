import pytest
from crypto import encrypt_file, decrypt_file

def test_encrypt_decrypt_hmac(tmp_path):
    file = tmp_path / "secret.txt"
    file.write_bytes(b"Top Secret Data!")

    password = "securepassword"

    encrypted = encrypt_file(str(file), password)
    decrypted = decrypt_file(encrypted, password)

    assert decrypted == b"Top Secret Data!"

def test_hmac_tampering_detected(tmp_path):
    file = tmp_path / "secret.txt"
    file.write_bytes(b"Important Info")
    password = "mypassword"

    encrypted = encrypt_file(str(file), password)

    # Tamper with ciphertext
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0xFF  # flip last byte

    import pytest
    with pytest.raises(ValueError):
        decrypt_file(bytes(tampered), password)
