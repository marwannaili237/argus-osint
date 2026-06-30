import pytest
class TestEncryption:
    def test_roundtrip(self):
        from argus.security.encryption import encrypt_data, decrypt_data
        e = encrypt_data("secret data")
        assert e != "secret data"
        assert decrypt_data(e) == "secret data"
    def test_same_input(self):
        from argus.security.encryption import encrypt_data
        assert encrypt_data("hello") == encrypt_data("hello")
    def test_invalid(self):
        from argus.security.encryption import decrypt_data
        assert decrypt_data("bad") == "" or isinstance(decrypt_data("bad"), str)
