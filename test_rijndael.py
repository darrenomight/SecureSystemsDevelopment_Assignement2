"""
Test suite for rijndael.c AES implementation.
Darren Bugeja - C21427252

Tests each AES step against the boppreh/aes reference implementation
using Python's ctypes module to call into the compiled C library.

Run with: pytest test_rijndael.py -v
"""

import ctypes
import os
import sys
import random
import pytest

# ----------------------------------------------------------------
# Load the compiled shared library
# ----------------------------------------------------------------
LIB_PATH = os.path.join(os.path.dirname(__file__), "rijndael.so")
try:
    rijndael = ctypes.CDLL(LIB_PATH)
except OSError as e:
    print(f"ERROR: Could not load rijndael.so — did you run 'make'? ({e})")
    sys.exit(1)

# ----------------------------------------------------------------
# Load the boppreh/aes reference implementation
# ----------------------------------------------------------------
REF_PATH = os.path.join(os.path.dirname(__file__), "aes-ref")
sys.path.insert(0, REF_PATH)
import aes as ref_aes

# ----------------------------------------------------------------
# AES block size enum values (must match rijndael.h)
# ----------------------------------------------------------------
AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def make_buffer(data: bytes) -> ctypes.Array:
    """Create a mutable ctypes buffer from bytes."""
    return ctypes.create_string_buffer(data)

def random_bytes(n: int) -> bytes:
    """Generate n random bytes."""
    return bytes(random.randint(0, 255) for _ in range(n))


# ================================================================
# TEST: sub_bytes
# Compare our C sub_bytes against the reference S-box lookup
# ================================================================

# Reference S-box from boppreh/aes
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

def ref_sub_bytes(block: bytes) -> bytes:
    return bytes(SBOX[b] for b in block)

class TestSubBytes:
    def _run(self, data):
        buf = make_buffer(data)
        rijndael.sub_bytes(buf, AES_BLOCK_128)
        return bytes(buf)

    def test_sub_bytes_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_sub_bytes(data)

    def test_sub_bytes_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_sub_bytes(data)

    def test_sub_bytes_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_sub_bytes(data)

    def test_sub_bytes_known(self):
        # Known input: all zeros should map to 0x63 for each byte
        data = bytes(16)
        result = self._run(data)
        assert all(b == 0x63 for b in result)


# ================================================================
# TEST: shift_rows
# Compare our C shift_rows against reference
# ================================================================

def ref_shift_rows(block: bytes) -> bytes:
    """Reference shift rows for AES-128 (4x4 matrix)."""
    b = list(block)
    # Row 1: shift left 1
    b[4], b[5], b[6], b[7] = b[5], b[6], b[7], b[4]
    # Row 2: shift left 2
    b[8], b[9], b[10], b[11] = b[10], b[11], b[8], b[9]
    # Row 3: shift left 3
    b[12], b[13], b[14], b[15] = b[15], b[12], b[13], b[14]
    return bytes(b)

class TestShiftRows:
    def _run(self, data):
        buf = make_buffer(data)
        rijndael.shift_rows(buf, AES_BLOCK_128)
        return bytes(buf)

    def test_shift_rows_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_shift_rows(data)

    def test_shift_rows_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_shift_rows(data)

    def test_shift_rows_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_shift_rows(data)

    def test_shift_rows_known(self):
        # Sequential bytes: easy to verify shifts manually
        data = bytes(range(16))
        assert self._run(data) == ref_shift_rows(data)


# ================================================================
# TEST: mix_columns
# Compare our C mix_columns against the reference implementation
# ================================================================

def ref_mix_columns(block: bytes) -> bytes:
    """
    Reference mix_columns using the boppreh AES internals.
    We create a minimal AES object and call its mix_columns directly.
    """
    # Access the internal mix_columns via the reference AES object
    aes_obj = ref_aes.AES(bytes(16))
    b = list(block)
    result = []

    def xtime(a):
        return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

    for c in range(4):
        s0 = b[0*4+c]; s1 = b[1*4+c]; s2 = b[2*4+c]; s3 = b[3*4+c]
        r = [0]*4
        r[0] = xtime(s0) ^ (xtime(s1)^s1) ^ s2 ^ s3
        r[1] = s0 ^ xtime(s1) ^ (xtime(s2)^s2) ^ s3
        r[2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3)^s3)
        r[3] = (xtime(s0)^s0) ^ s1 ^ s2 ^ xtime(s3)
        for row in range(4):
            b[row*4+c] = r[row]

    return bytes(b)

class TestMixColumns:
    def _run(self, data):
        buf = make_buffer(data)
        rijndael.mix_columns(buf, AES_BLOCK_128)
        return bytes(buf)

    def test_mix_columns_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_mix_columns(data)

    def test_mix_columns_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_mix_columns(data)

    def test_mix_columns_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_mix_columns(data)


# ================================================================
# TEST: Full encrypt and decrypt round-trip
# Encrypt with our C code, compare against boppreh reference,
# then decrypt and verify we recover the original plaintext.
# ================================================================

rijndael.aes_encrypt_block.restype = ctypes.c_char_p
rijndael.aes_decrypt_block.restype = ctypes.c_char_p

def c_encrypt(plaintext: bytes, key: bytes) -> bytes:
    pt_buf = make_buffer(plaintext)
    key_buf = make_buffer(key)
    result_ptr = rijndael.aes_encrypt_block(pt_buf, key_buf, AES_BLOCK_128)
    return ctypes.string_at(result_ptr, 16)

def c_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    ct_buf = make_buffer(ciphertext)
    key_buf = make_buffer(key)
    result_ptr = rijndael.aes_decrypt_block(ct_buf, key_buf, AES_BLOCK_128)
    return ctypes.string_at(result_ptr, 16)

def ref_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return ref_aes.AES(key).encrypt_block(plaintext)

def ref_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return ref_aes.AES(key).decrypt_block(ciphertext)

class TestEncryptDecrypt:
    def test_encrypt_matches_reference_1(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        assert c_encrypt(pt, key) == ref_encrypt(pt, key)

    def test_encrypt_matches_reference_2(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        assert c_encrypt(pt, key) == ref_encrypt(pt, key)

    def test_encrypt_matches_reference_3(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        assert c_encrypt(pt, key) == ref_encrypt(pt, key)

    def test_decrypt_matches_reference_1(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        ct  = ref_encrypt(pt, key)
        assert c_decrypt(ct, key) == ref_decrypt(ct, key)

    def test_decrypt_matches_reference_2(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        ct  = ref_encrypt(pt, key)
        assert c_decrypt(ct, key) == ref_decrypt(ct, key)

    def test_decrypt_matches_reference_3(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        ct  = ref_encrypt(pt, key)
        assert c_decrypt(ct, key) == ref_decrypt(ct, key)

    def test_roundtrip_1(self):
        """Encrypt then decrypt should recover original plaintext."""
        pt  = random_bytes(16)
        key = random_bytes(16)
        assert c_decrypt(c_encrypt(pt, key), key) == pt

    def test_roundtrip_2(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        assert c_decrypt(c_encrypt(pt, key), key) == pt

    def test_roundtrip_3(self):
        pt  = random_bytes(16)
        key = random_bytes(16)
        assert c_decrypt(c_encrypt(pt, key), key) == pt

    def test_known_vector(self):
        """NIST known test vector for AES-128."""
        pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        expected = bytes.fromhex("69c4e0d86a7b04300d8a8b41b570efde")
        assert c_encrypt(pt, key) == expected
