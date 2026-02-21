"""Tuya protocol encryption and cryptographic operations."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import GCM_NONCE_SIZE, UDP_KEY

if TYPE_CHECKING:
    pass


class TuyaCipher:
    """Handles all Tuya protocol encryption/decryption operations."""

    def __init__(self, local_key: bytes) -> None:
        """Initialize with the device's local key (16 bytes)."""
        if len(local_key) != 16:
            raise ValueError("Local key must be exactly 16 bytes")
        self._local_key = local_key

    @property
    def local_key(self) -> bytes:
        """Return the local key."""
        return self._local_key

    # --- AES-ECB operations (v3.3 and v3.4) ---

    def encrypt_ecb(self, plaintext: bytes, key: bytes | None = None) -> bytes:
        """Encrypt data using AES-128-ECB with PKCS7 padding."""
        use_key = key or self._local_key
        padded = self._pkcs7_pad(plaintext, 16)
        cipher = Cipher(algorithms.AES(use_key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def decrypt_ecb(self, ciphertext: bytes, key: bytes | None = None) -> bytes:
        """Decrypt data using AES-128-ECB with PKCS7 unpadding."""
        use_key = key or self._local_key
        cipher = Cipher(algorithms.AES(use_key), modes.ECB())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        return self._pkcs7_unpad(padded)

    # --- AES-GCM operations (v3.5) ---

    def encrypt_gcm(
        self, plaintext: bytes, key: bytes, iv: bytes, aad: bytes | None = None
    ) -> tuple[bytes, bytes]:
        """Encrypt data using AES-128-GCM. Returns (ciphertext, tag)."""
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(iv, plaintext, aad)
        # AESGCM appends 16-byte tag to ciphertext
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        return ciphertext, tag

    def decrypt_gcm(
        self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, aad: bytes | None = None
    ) -> bytes:
        """Decrypt data using AES-128-GCM."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext + tag, aad)

    # --- Integrity verification ---

    @staticmethod
    def calc_crc32(data: bytes) -> bytes:
        """Calculate CRC32 checksum for v3.3 packet integrity."""
        import binascii

        crc = binascii.crc32(data) & 0xFFFFFFFF
        return struct.pack(">I", crc)

    @staticmethod
    def calc_hmac(key: bytes, data: bytes) -> bytes:
        """Calculate HMAC-SHA256 for v3.4/v3.5 packet integrity."""
        return hmac.new(key, data, hashlib.sha256).digest()

    # --- UDP broadcast decryption ---

    @staticmethod
    def decrypt_udp(data: bytes) -> bytes:
        """Decrypt UDP broadcast data using the fixed UDP key (AES-ECB)."""
        cipher = Cipher(algorithms.AES(UDP_KEY), modes.ECB())
        decryptor = cipher.decryptor()
        padded = decryptor.update(data) + decryptor.finalize()
        return TuyaCipher._pkcs7_unpad(padded)

    # --- Session key negotiation ---

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a 16-byte random nonce for session key negotiation."""
        return os.urandom(16)

    def derive_session_key_v34(self, client_nonce: bytes, device_nonce: bytes) -> bytes:
        """Derive session key for v3.4: AES_ECB(local_key, client_nonce XOR device_nonce)."""
        xored = bytes(a ^ b for a, b in zip(client_nonce, device_nonce))
        # Encrypt without padding — input is already 16 bytes
        cipher = Cipher(algorithms.AES(self._local_key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(xored) + encryptor.finalize()

    def derive_session_key_v35(self, client_nonce: bytes, device_nonce: bytes) -> bytes:
        """Derive session key for v3.5 using AES-GCM.

        XOR nonces, encrypt with local_key using AES-GCM,
        IV = client_nonce[:12], take bytes [0:16] of ciphertext.
        """
        xored = bytes(a ^ b for a, b in zip(client_nonce, device_nonce))
        iv = client_nonce[:GCM_NONCE_SIZE]
        aesgcm = AESGCM(self._local_key)
        ct_with_tag = aesgcm.encrypt(iv, xored, None)
        # Take first 16 bytes of ciphertext (excluding tag)
        return ct_with_tag[:16]

    # --- PKCS7 padding ---

    @staticmethod
    def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
        """Apply PKCS7 padding."""
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        """Remove PKCS7 padding."""
        if not data:
            return data
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            return data  # Invalid padding, return as-is
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            return data  # Invalid padding, return as-is
        return data[:-pad_len]
