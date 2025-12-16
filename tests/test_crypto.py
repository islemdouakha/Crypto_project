import pytest
from crypto import encrypt_file, decrypt_file

def test_encrypt_decrypt_cycle(tmp_path):
    file = tmp_path / "test.txt"
    file.write_bytes(b"Hello Secure World!")

    password = "strongpassword"

    encrypted = encrypt_file(str(file), password)
    decrypted = decrypt_file(encrypted, password)

    assert decrypted == b"Hello Secure World!"
