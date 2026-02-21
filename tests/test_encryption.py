"""Tests for Tuya protocol encryption."""

from __future__ import annotations

import pytest

from custom_components.lsc_tuya_doorbell.protocol.encryption import TuyaCipher
from custom_components.lsc_tuya_doorbell.protocol.constants import UDP_KEY


class TestTuyaCipher:
    """Test TuyaCipher encryption operations."""

    def test_init_valid_key(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        assert cipher.local_key == local_key

    def test_init_invalid_key_length(self) -> None:
        with pytest.raises(ValueError, match="16 bytes"):
            TuyaCipher(b"short")

    def test_ecb_roundtrip(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        plaintext = b"Hello, Tuya protocol!"
        encrypted = cipher.encrypt_ecb(plaintext)
        decrypted = cipher.decrypt_ecb(encrypted)
        assert decrypted == plaintext

    def test_ecb_roundtrip_with_custom_key(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        custom_key = b"abcdefghijklmnop"
        plaintext = b"Testing with custom key"
        encrypted = cipher.encrypt_ecb(plaintext, key=custom_key)
        decrypted = cipher.decrypt_ecb(encrypted, key=custom_key)
        assert decrypted == plaintext

    def test_ecb_empty_plaintext(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        # Empty input gets padded to one block
        encrypted = cipher.encrypt_ecb(b"")
        decrypted = cipher.decrypt_ecb(encrypted)
        assert decrypted == b""

    def test_ecb_block_aligned_plaintext(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        # Exactly 16 bytes — PKCS7 adds a full padding block
        plaintext = b"0123456789abcdef"
        encrypted = cipher.encrypt_ecb(plaintext)
        decrypted = cipher.decrypt_ecb(encrypted)
        assert decrypted == plaintext

    def test_ecb_large_plaintext(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        plaintext = b"x" * 1024
        encrypted = cipher.encrypt_ecb(plaintext)
        decrypted = cipher.decrypt_ecb(encrypted)
        assert decrypted == plaintext


class TestGCM:
    """Test AES-GCM operations for v3.5."""

    def test_gcm_roundtrip(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        key = local_key
        iv = b"123456789012"  # 12 bytes
        plaintext = b"GCM test payload"
        aad = b"additional data"

        ciphertext, tag = cipher.encrypt_gcm(plaintext, key, iv, aad)
        decrypted = cipher.decrypt_gcm(ciphertext, key, iv, tag, aad)
        assert decrypted == plaintext

    def test_gcm_wrong_key_fails(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        iv = b"123456789012"
        plaintext = b"test"
        ciphertext, tag = cipher.encrypt_gcm(plaintext, local_key, iv)

        wrong_key = b"wrongkeywrongkey"
        with pytest.raises(Exception):
            cipher.decrypt_gcm(ciphertext, wrong_key, iv, tag)


class TestIntegrity:
    """Test CRC32 and HMAC operations."""

    def test_crc32_deterministic(self) -> None:
        data = b"test data for crc"
        crc1 = TuyaCipher.calc_crc32(data)
        crc2 = TuyaCipher.calc_crc32(data)
        assert crc1 == crc2
        assert len(crc1) == 4

    def test_crc32_different_data(self) -> None:
        crc1 = TuyaCipher.calc_crc32(b"data1")
        crc2 = TuyaCipher.calc_crc32(b"data2")
        assert crc1 != crc2

    def test_hmac_deterministic(self) -> None:
        key = b"0123456789abcdef"
        data = b"test data for hmac"
        hmac1 = TuyaCipher.calc_hmac(key, data)
        hmac2 = TuyaCipher.calc_hmac(key, data)
        assert hmac1 == hmac2
        assert len(hmac1) == 32  # SHA256

    def test_hmac_different_key(self) -> None:
        data = b"test data"
        hmac1 = TuyaCipher.calc_hmac(b"key1key1key1key1", data)
        hmac2 = TuyaCipher.calc_hmac(b"key2key2key2key2", data)
        assert hmac1 != hmac2


class TestUDPDecryption:
    """Test UDP broadcast decryption."""

    def test_udp_key_is_16_bytes(self) -> None:
        assert len(UDP_KEY) == 16

    def test_udp_encrypt_decrypt_roundtrip(self) -> None:
        # Simulate what a Tuya device sends: encrypt with UDP key
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        plaintext = b'{"ip":"192.168.1.100","gwId":"abc123","version":"3.3"}'
        # Pad
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)
        # Encrypt with UDP key
        cipher = Cipher(algorithms.AES(UDP_KEY), modes.ECB())
        enc = cipher.encryptor()
        encrypted = enc.update(padded) + enc.finalize()

        # Now decrypt with our method
        decrypted = TuyaCipher.decrypt_udp(encrypted)
        assert decrypted == plaintext


class TestSessionKeys:
    """Test session key derivation."""

    def test_generate_nonce(self) -> None:
        nonce = TuyaCipher.generate_nonce()
        assert len(nonce) == 16
        # Two nonces should be different
        nonce2 = TuyaCipher.generate_nonce()
        assert nonce != nonce2

    def test_session_key_v34(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        client = b"client_nonce_123"
        device = b"device_nonce_456"
        key = cipher.derive_session_key_v34(client, device)
        assert len(key) == 16
        # Same input should give same output
        key2 = cipher.derive_session_key_v34(client, device)
        assert key == key2

    def test_session_key_v35(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        client = b"client_nonce_123"
        device = b"device_nonce_456"
        key = cipher.derive_session_key_v35(client, device)
        assert len(key) == 16

    def test_session_keys_differ_v34_v35(self, local_key: bytes) -> None:
        cipher = TuyaCipher(local_key)
        client = b"client_nonce_123"
        device = b"device_nonce_456"
        key34 = cipher.derive_session_key_v34(client, device)
        key35 = cipher.derive_session_key_v35(client, device)
        assert key34 != key35


class TestPKCS7:
    """Test PKCS7 padding/unpadding."""

    def test_pad_unpad_roundtrip(self) -> None:
        for size in range(0, 33):
            data = bytes(range(size % 256)) * (size // 256 + 1)
            data = data[:size]
            padded = TuyaCipher._pkcs7_pad(data, 16)
            assert len(padded) % 16 == 0
            unpadded = TuyaCipher._pkcs7_unpad(padded)
            assert unpadded == data

    def test_invalid_padding_returns_data(self) -> None:
        # Data with invalid padding byte should be returned as-is
        data = b"no valid padding here!!"
        result = TuyaCipher._pkcs7_unpad(data)
        assert result == data
