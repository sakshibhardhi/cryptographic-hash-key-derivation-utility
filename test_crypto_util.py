#!/usr/bin/env python3
"""
test_crypto_util.py
===================
Unit tests for cryptoutil using standard NIST/RFC test vectors.

Run with:
    python -m unittest -v
or:
    python -m unittest test_crypto_util -v
"""

import hashlib
import hmac as hmac_mod
import os
import sys
import tempfile
import unittest

# Make sure the sibling module is importable when running from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_util import (
    hash_text,
    hash_file,
    generate_salt,
    derive_key,
    compute_hmac,
    verify_hmac,
    verify_checksum,
    parse_hex_salt,
    validate_iterations,
)


# ===========================================================================
# Hash tests
# ===========================================================================

class TestHashText(unittest.TestCase):
    """Standard NIST test vectors for SHA-256 and SHA-512."""

    # SHA-256 vectors
    SHA256_VECTORS = [
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ]

    # SHA-512 vectors
    SHA512_VECTORS = [
        (
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
    ]

    def test_sha256_abc(self):
        text, expected = self.SHA256_VECTORS[0]
        self.assertEqual(hash_text(text, "sha256"), expected)

    def test_sha256_empty(self):
        text, expected = self.SHA256_VECTORS[1]
        self.assertEqual(hash_text(text, "sha256"), expected)

    def test_sha512_abc(self):
        text, expected = self.SHA512_VECTORS[0]
        self.assertEqual(hash_text(text, "sha512"), expected)

    def test_sha512_empty(self):
        text, expected = self.SHA512_VECTORS[1]
        self.assertEqual(hash_text(text, "sha512"), expected)

    def test_default_algo_is_sha256(self):
        """hash_text defaults to SHA-256."""
        _, expected = self.SHA256_VECTORS[0]
        self.assertEqual(hash_text("abc"), expected)

    def test_returns_lowercase_hex(self):
        result = hash_text("hello")
        self.assertEqual(result, result.lower())
        # Verify it's a valid hex string
        int(result, 16)

    def test_sha256_digest_length(self):
        self.assertEqual(len(hash_text("test", "sha256")), 64)

    def test_sha512_digest_length(self):
        self.assertEqual(len(hash_text("test", "sha512")), 128)


class TestHashFile(unittest.TestCase):
    """File hashing tests: empty file, normal file, large file (> chunk size)."""

    def _write_temp(self, content: bytes) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        return path

    def test_empty_file_sha256(self):
        path = self._write_temp(b"")
        try:
            result = hash_file(path, "sha256")
            expected = hashlib.sha256(b"").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_empty_file_sha512(self):
        path = self._write_temp(b"")
        try:
            result = hash_file(path, "sha512")
            expected = hashlib.sha512(b"").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_small_file(self):
        content = b"The quick brown fox jumps over the lazy dog"
        path = self._write_temp(content)
        try:
            result = hash_file(path, "sha256")
            expected = hashlib.sha256(content).hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_large_file_exceeds_chunk_size(self):
        """File larger than 64 KB chunk size must hash correctly."""
        # 200 KB of repeating data
        content = b"A" * (200 * 1024)
        path = self._write_temp(content)
        try:
            result = hash_file(path, "sha256")
            expected = hashlib.sha256(content).hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_large_file_sha512(self):
        content = b"B" * (200 * 1024)
        path = self._write_temp(content)
        try:
            result = hash_file(path, "sha512")
            expected = hashlib.sha512(content).hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            hash_file("/nonexistent/path/that/does/not/exist.bin", "sha256")

    def test_matches_hash_text_for_utf8_content(self):
        """hash_file and hash_text must agree on UTF-8 encoded content."""
        text = "hello, cryptoutil!"
        content = text.encode("utf-8")
        path = self._write_temp(content)
        try:
            self.assertEqual(hash_file(path, "sha256"), hash_text(text, "sha256"))
        finally:
            os.unlink(path)


# ===========================================================================
# Salt generator tests
# ===========================================================================

class TestGenerateSalt(unittest.TestCase):

    def test_default_length(self):
        salt = generate_salt()
        self.assertEqual(len(salt), 16)

    def test_custom_length(self):
        for n in [8, 16, 24, 32, 64]:
            with self.subTest(n=n):
                self.assertEqual(len(generate_salt(n)), n)

    def test_returns_bytes(self):
        self.assertIsInstance(generate_salt(16), bytes)

    def test_two_salts_differ(self):
        """Consecutive salts must not be equal (statistically certain for 16+ bytes)."""
        salt1 = generate_salt(16)
        salt2 = generate_salt(16)
        self.assertNotEqual(salt1, salt2)

    def test_uses_secrets_not_random(self):
        """Verify generate_salt uses the secrets module (import-level check)."""
        import crypto_util
        import inspect
        source = inspect.getsource(crypto_util.generate_salt)
        self.assertIn("secrets", source)


# ===========================================================================
# PBKDF2-HMAC key derivation tests
# ===========================================================================

class TestDeriveKey(unittest.TestCase):
    """
    Test vectors from RFC 7914 / PKCS #5 known-answer tests.

    PBKDF2-HMAC-SHA256:
      password = "password", salt = b"salt"
      iterations=1,  dklen=32 -> 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
      iterations=2,  dklen=32 -> ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
    """

    SALT = b"salt"
    PASSWORD = "password"

    VECTOR_ITER1 = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    VECTOR_ITER2 = "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"

    def test_pbkdf2_sha256_iter1(self):
        dk = derive_key(self.PASSWORD, self.SALT, iterations=1, algo="sha256", length=32)
        self.assertEqual(dk.hex(), self.VECTOR_ITER1)

    def test_pbkdf2_sha256_iter2(self):
        dk = derive_key(self.PASSWORD, self.SALT, iterations=2, algo="sha256", length=32)
        self.assertEqual(dk.hex(), self.VECTOR_ITER2)

    def test_returns_bytes(self):
        dk = derive_key(self.PASSWORD, self.SALT, iterations=1, algo="sha256", length=32)
        self.assertIsInstance(dk, bytes)

    def test_requested_length_honored(self):
        for length in [16, 32, 64]:
            with self.subTest(length=length):
                dk = derive_key(self.PASSWORD, self.SALT, iterations=1, algo="sha256", length=length)
                self.assertEqual(len(dk), length)

    def test_different_passwords_different_keys(self):
        dk1 = derive_key("password1", self.SALT, iterations=1, algo="sha256", length=32)
        dk2 = derive_key("password2", self.SALT, iterations=1, algo="sha256", length=32)
        self.assertNotEqual(dk1, dk2)

    def test_different_salts_different_keys(self):
        dk1 = derive_key(self.PASSWORD, b"salt1", iterations=1, algo="sha256", length=32)
        dk2 = derive_key(self.PASSWORD, b"salt2", iterations=1, algo="sha256", length=32)
        self.assertNotEqual(dk1, dk2)

    def test_sha512_variant(self):
        """SHA-512 variant produces a different key than SHA-256."""
        dk_256 = derive_key(self.PASSWORD, self.SALT, iterations=1, algo="sha256", length=32)
        dk_512 = derive_key(self.PASSWORD, self.SALT, iterations=1, algo="sha512", length=32)
        self.assertNotEqual(dk_256, dk_512)


# ===========================================================================
# HMAC tests
# ===========================================================================

class TestComputeHmac(unittest.TestCase):
    """
    RFC 4231 Test Case 2:
      Key  = "Jefe" (UTF-8)
      Data = "what do ya want for nothing?" (UTF-8)
      HMAC-SHA256 = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    """

    KEY = b"Jefe"
    DATA = b"what do ya want for nothing?"
    EXPECTED_SHA256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

    def test_rfc4231_tc2_sha256(self):
        result = compute_hmac(self.KEY, self.DATA, "sha256")
        self.assertEqual(result, self.EXPECTED_SHA256)

    def test_returns_lowercase_hex(self):
        result = compute_hmac(self.KEY, self.DATA, "sha256")
        self.assertEqual(result, result.lower())

    def test_sha256_digest_length(self):
        result = compute_hmac(self.KEY, self.DATA, "sha256")
        self.assertEqual(len(result), 64)

    def test_sha512_digest_length(self):
        result = compute_hmac(self.KEY, self.DATA, "sha512")
        self.assertEqual(len(result), 128)

    def test_different_key_different_hmac(self):
        h1 = compute_hmac(b"key1", self.DATA, "sha256")
        h2 = compute_hmac(b"key2", self.DATA, "sha256")
        self.assertNotEqual(h1, h2)

    def test_different_data_different_hmac(self):
        h1 = compute_hmac(self.KEY, b"message1", "sha256")
        h2 = compute_hmac(self.KEY, b"message2", "sha256")
        self.assertNotEqual(h1, h2)


class TestVerifyHmac(unittest.TestCase):

    KEY = b"Jefe"
    DATA = b"what do ya want for nothing?"
    CORRECT = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

    def test_valid_hmac_returns_true(self):
        self.assertTrue(verify_hmac(self.KEY, self.DATA, self.CORRECT, "sha256"))

    def test_uppercase_expected_still_valid(self):
        """Verify is case-insensitive on the expected hex."""
        self.assertTrue(verify_hmac(self.KEY, self.DATA, self.CORRECT.upper(), "sha256"))

    def test_tampered_message_returns_false(self):
        tampered = b"what do ya want for something?"
        self.assertFalse(verify_hmac(self.KEY, tampered, self.CORRECT, "sha256"))

    def test_wrong_key_returns_false(self):
        self.assertFalse(verify_hmac(b"WrongKey", self.DATA, self.CORRECT, "sha256"))

    def test_wrong_digest_returns_false(self):
        wrong_hex = "0" * 64
        self.assertFalse(verify_hmac(self.KEY, self.DATA, wrong_hex, "sha256"))


# ===========================================================================
# Checksum verification tests
# ===========================================================================

class TestVerifyChecksum(unittest.TestCase):

    def _write_temp(self, content: bytes) -> str:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        return path

    def test_correct_checksum_returns_true(self):
        content = b"hello from cryptoutil"
        path = self._write_temp(content)
        try:
            expected = hashlib.sha256(content).hexdigest()
            match, computed = verify_checksum(path, expected, "sha256")
            self.assertTrue(match)
            self.assertEqual(computed, expected)
        finally:
            os.unlink(path)

    def test_incorrect_checksum_returns_false(self):
        content = b"hello from cryptoutil"
        path = self._write_temp(content)
        try:
            wrong_hex = "a" * 64
            match, computed = verify_checksum(path, wrong_hex, "sha256")
            self.assertFalse(match)
        finally:
            os.unlink(path)

    def test_uppercase_checksum_accepted(self):
        """Comparison is case-insensitive."""
        content = b"case insensitive test"
        path = self._write_temp(content)
        try:
            expected = hashlib.sha256(content).hexdigest().upper()
            match, _ = verify_checksum(path, expected, "sha256")
            self.assertTrue(match)
        finally:
            os.unlink(path)

    def test_sha512_checksum(self):
        content = b"sha512 checksum test"
        path = self._write_temp(content)
        try:
            expected = hashlib.sha512(content).hexdigest()
            match, computed = verify_checksum(path, expected, "sha512")
            self.assertTrue(match)
            self.assertEqual(computed, expected)
        finally:
            os.unlink(path)

    def test_file_not_found_raises(self):
        with self.assertRaises(FileNotFoundError):
            verify_checksum("/no/such/file.bin", "a" * 64, "sha256")


# ===========================================================================
# Input validation tests
# ===========================================================================

class TestParseHexSalt(unittest.TestCase):

    def test_valid_hex_string(self):
        result = parse_hex_salt("deadbeef")
        self.assertEqual(result, bytes.fromhex("deadbeef"))

    def test_invalid_hex_raises(self):
        with self.assertRaises(ValueError):
            parse_hex_salt("zzzzzzzz")

    def test_empty_string(self):
        result = parse_hex_salt("")
        self.assertEqual(result, b"")

    def test_odd_length_raises(self):
        """Odd-length hex strings are invalid."""
        with self.assertRaises(ValueError):
            parse_hex_salt("abc")  # 3 chars is not valid hex bytes

    def test_uppercase_hex_accepted(self):
        result = parse_hex_salt("DEADBEEF")
        self.assertEqual(result, bytes.fromhex("DEADBEEF"))


class TestValidateIterations(unittest.TestCase):

    def test_positive_integer_passes(self):
        # Should not raise
        validate_iterations(1)
        validate_iterations(1000)
        validate_iterations(600_000)

    def test_zero_raises(self):
        with self.assertRaises(ValueError):
            validate_iterations(0)

    def test_negative_raises(self):
        with self.assertRaises(ValueError):
            validate_iterations(-1)

    def test_large_value_passes(self):
        validate_iterations(10_000_000)


# ===========================================================================
# Integration / edge case tests
# ===========================================================================

class TestIntegration(unittest.TestCase):

    def test_hash_text_vs_hash_file_consistency(self):
        """hash_text and hash_file must produce identical results for the same content."""
        text = "consistency check"
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(text.encode("utf-8"))
            self.assertEqual(hash_text(text, "sha256"), hash_file(path, "sha256"))
            self.assertEqual(hash_text(text, "sha512"), hash_file(path, "sha512"))
        finally:
            os.unlink(path)

    def test_kdf_with_generated_salt(self):
        """Full round-trip: generate salt, derive key, re-derive with same salt."""
        salt = generate_salt(16)
        dk1 = derive_key("password", salt, iterations=1, algo="sha256", length=32)
        dk2 = derive_key("password", salt, iterations=1, algo="sha256", length=32)
        self.assertEqual(dk1, dk2)

    def test_kdf_different_salts_differ(self):
        salt1 = generate_salt(16)
        salt2 = generate_salt(16)
        dk1 = derive_key("password", salt1, iterations=1, algo="sha256", length=32)
        dk2 = derive_key("password", salt2, iterations=1, algo="sha256", length=32)
        # Extremely unlikely to collide; treat as guaranteed for 16-byte random salts
        self.assertNotEqual(dk1, dk2)

    def test_hmac_compute_then_verify(self):
        key = b"integration-test-key"
        message = b"integration test message"
        digest = compute_hmac(key, message, "sha256")
        self.assertTrue(verify_hmac(key, message, digest, "sha256"))

    def test_hmac_verify_rejects_altered_message(self):
        key = b"integration-test-key"
        message = b"original message"
        digest = compute_hmac(key, message, "sha256")
        self.assertFalse(verify_hmac(key, b"altered message", digest, "sha256"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
