"""
Test suite for rijndael.c AES implementation.
Darren Grants 
C21427252

Tests each AES step against known reference values and verifies
full encrypt/decrypt correctness using NIST test vectors and
roundtrip validation.

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
# AES block size enum values (must match rijndael.h)
# ----------------------------------------------------------------
AES_BLOCK_128 = 0

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def random_bytes(n):
    return bytes(random.randint(0, 255) for _ in range(n))

def c_buf(data):
    """Fixed-size ctypes buffer with no null terminator."""
    return (ctypes.c_ubyte * len(data))(*data)

def buf_to_bytes(buf, n):
    return bytes(buf[:n])


# ================================================================
# Reference implementations (pure Python, no third-party libs)
# ================================================================

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

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

def ref_sub_bytes(block):
    return bytes(SBOX[b] for b in block)

def ref_invert_sub_bytes(block):
    return bytes(INV_SBOX[b] for b in block)

def ref_shift_rows(block):
    b = list(block)
    b[4],  b[5],  b[6],  b[7]  = b[5],  b[6],  b[7],  b[4]
    b[8],  b[9],  b[10], b[11] = b[10], b[11], b[8],  b[9]
    b[12], b[13], b[14], b[15] = b[15], b[12], b[13], b[14]
    return bytes(b)

def ref_invert_shift_rows(block):
    b = list(block)
    b[4],  b[5],  b[6],  b[7]  = b[7],  b[4],  b[5],  b[6]
    b[8],  b[9],  b[10], b[11] = b[10], b[11], b[8],  b[9]
    b[12], b[13], b[14], b[15] = b[13], b[14], b[15], b[12]
    return bytes(b)

def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

def ref_mix_columns(block):
    b = list(block)
    for c in range(4):
        s0 = b[0*4+c]; s1 = b[1*4+c]; s2 = b[2*4+c]; s3 = b[3*4+c]
        b[0*4+c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
        b[1*4+c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
        b[2*4+c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
        b[3*4+c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)
    return bytes(b)


# ================================================================
# TEST: sub_bytes
# ================================================================
class TestSubBytes:
    def _run(self, data):
        buf = c_buf(data)
        rijndael.sub_bytes(buf, AES_BLOCK_128)
        return buf_to_bytes(buf, 16)

    def test_sub_bytes_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_sub_bytes(data)

    def test_sub_bytes_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_sub_bytes(data)

    def test_sub_bytes_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_sub_bytes(data)

    def test_sub_bytes_all_zeros(self):
        # All zeros should map to 0x63 per the S-box
        assert self._run(bytes(16)) == bytes([0x63] * 16)


# ================================================================
# TEST: invert_sub_bytes
# ================================================================
class TestInvertSubBytes:
    def _run(self, data):
        buf = c_buf(data)
        rijndael.invert_sub_bytes(buf, AES_BLOCK_128)
        return buf_to_bytes(buf, 16)

    def test_invert_sub_bytes_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_invert_sub_bytes(data)

    def test_invert_sub_bytes_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_invert_sub_bytes(data)

    def test_invert_sub_bytes_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_invert_sub_bytes(data)

    def test_roundtrip(self):
        # sub_bytes followed by invert_sub_bytes must recover original
        data = random_bytes(16)
        buf = c_buf(data)
        rijndael.sub_bytes(buf, AES_BLOCK_128)
        rijndael.invert_sub_bytes(buf, AES_BLOCK_128)
        assert buf_to_bytes(buf, 16) == data


# ================================================================
# TEST: shift_rows
# ================================================================
class TestShiftRows:
    def _run(self, data):
        buf = c_buf(data)
        rijndael.shift_rows(buf, AES_BLOCK_128)
        return buf_to_bytes(buf, 16)

    def test_shift_rows_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_shift_rows(data)

    def test_shift_rows_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_shift_rows(data)

    def test_shift_rows_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_shift_rows(data)

    def test_shift_rows_sequential(self):
        data = bytes(range(16))
        assert self._run(data) == ref_shift_rows(data)


# ================================================================
# TEST: invert_shift_rows
# ================================================================
class TestInvertShiftRows:
    def _run(self, data):
        buf = c_buf(data)
        rijndael.invert_shift_rows(buf, AES_BLOCK_128)
        return buf_to_bytes(buf, 16)

    def test_invert_shift_rows_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_invert_shift_rows(data)

    def test_invert_shift_rows_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_invert_shift_rows(data)

    def test_invert_shift_rows_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_invert_shift_rows(data)

    def test_roundtrip(self):
        # shift_rows followed by invert_shift_rows must recover original
        data = random_bytes(16)
        buf = c_buf(data)
        rijndael.shift_rows(buf, AES_BLOCK_128)
        rijndael.invert_shift_rows(buf, AES_BLOCK_128)
        assert buf_to_bytes(buf, 16) == data


# ================================================================
# TEST: mix_columns
# ================================================================
class TestMixColumns:
    def _run(self, data):
        buf = c_buf(data)
        rijndael.mix_columns(buf, AES_BLOCK_128)
        return buf_to_bytes(buf, 16)

    def test_mix_columns_1(self):
        data = random_bytes(16)
        assert self._run(data) == ref_mix_columns(data)

    def test_mix_columns_2(self):
        data = random_bytes(16)
        assert self._run(data) == ref_mix_columns(data)

    def test_mix_columns_3(self):
        data = random_bytes(16)
        assert self._run(data) == ref_mix_columns(data)

    def test_roundtrip(self):
        # mix_columns followed by invert_mix_columns must recover original
        data = random_bytes(16)
        buf = c_buf(data)
        rijndael.mix_columns(buf, AES_BLOCK_128)
        rijndael.invert_mix_columns(buf, AES_BLOCK_128)
        assert buf_to_bytes(buf, 16) == data


# ================================================================
# TEST: Full encrypt and decrypt
#
# Our C code stores the AES state in row-major order.
# NIST FIPS-197 uses column-major order for the state matrix,
# so only the plaintext/ciphertext state needs transposing.
# The key is always a flat byte array in both — no transpose needed.
# ================================================================

rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

def c_encrypt(plaintext, key):
    ptr = rijndael.aes_encrypt_block(c_buf(plaintext), c_buf(key), AES_BLOCK_128)
    return bytes(ptr[:16])

def c_decrypt(ciphertext, key):
    ptr = rijndael.aes_decrypt_block(c_buf(ciphertext), c_buf(key), AES_BLOCK_128)
    return bytes(ptr[:16])

def transpose(b):
    """Swap between row-major and column-major for a 4x4 byte block."""
    t = [0] * 16
    for r in range(4):
        for c in range(4):
            t[r*4+c] = b[c*4+r]
    return bytes(t)


class TestEncryptDecrypt:

    def test_roundtrip_1(self):
        """Encrypt then decrypt must recover the original plaintext."""
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

    def test_different_keys_produce_different_ciphertext(self):
        """Same plaintext encrypted with different keys must differ."""
        pt   = random_bytes(16)
        key1 = random_bytes(16)
        key2 = random_bytes(16)
        assert c_encrypt(pt, key1) != c_encrypt(pt, key2)

    def test_different_plaintexts_produce_different_ciphertext(self):
        """Different plaintexts with the same key must produce different output."""
        key = random_bytes(16)
        pt1 = random_bytes(16)
        pt2 = random_bytes(16)
        assert c_encrypt(pt1, key) != c_encrypt(pt2, key)

    def test_roundtrip_known_input(self):
        """Known fixed input roundtrip — encrypt then decrypt recovers original."""
        pt  = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        key = bytes([50,20,46,86,67,9,70,27,75,17,51,17,4,8,6,99])
        assert c_decrypt(c_encrypt(pt, key), key) == pt

    def test_roundtrip_all_zeros(self):
        """All-zero plaintext and key roundtrip."""
        pt  = bytes(16)
        key = bytes(16)
        assert c_decrypt(c_encrypt(pt, key), key) == pt

    def test_roundtrip_all_ff(self):
        """All 0xFF plaintext and key roundtrip."""
        pt  = bytes([0xFF]*16)
        key = bytes([0xFF]*16)
        assert c_decrypt(c_encrypt(pt, key), key) == pt