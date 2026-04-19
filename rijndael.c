/*
  Darren Grants
  C21427252
  Rijndael (AES) implementation in C.
  Implements AES-128, AES-256, and AES-512 block encryption and decryption.
 */

#include "rijndael.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================
 * S-Box and Inverse S-Box lookup tables
 * These are the standard Rijndael substitution tables.
 * Each byte of the block is replaced using these tables
 * during the SubBytes and InvSubBytes steps.
 * ========================================================= */

static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const unsigned char inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

/* Round constants used in key expansion */
static const unsigned char rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                       0x20, 0x40, 0x80, 0x1b, 0x36};

/* =========================================================
 * Helper: block size in bytes
 * ========================================================= */
size_t block_size_to_bytes(aes_block_size_t block_size) {
  switch (block_size) {
    case AES_BLOCK_128:
      return 16;
    case AES_BLOCK_256:
      return 32;
    case AES_BLOCK_512:
      return 64;
    default:
      fprintf(stderr, "Invalid block size %d\n", block_size);
      exit(1);
  }
}

/* =========================================================
 * Helper: number of columns (Nb) for a given block size
 * AES-128 = 4 columns, AES-256 = 8, AES-512 = 16
 * ========================================================= */
static int block_cols(aes_block_size_t block_size) {
  switch (block_size) {
    case AES_BLOCK_128:
      return 4;
    case AES_BLOCK_256:
      return 8;
    case AES_BLOCK_512:
      return 16;
    default:
      fprintf(stderr, "Invalid block size\n");
      exit(1);
  }
}

/* =========================================================
 * Helper: number of rounds for a given block size
 * AES-128 = 10 rounds, AES-256 = 14, AES-512 = 22
 * ========================================================= */
static int num_rounds(aes_block_size_t block_size) {
  switch (block_size) {
    case AES_BLOCK_128:
      return 10;
    case AES_BLOCK_256:
      return 14;
    case AES_BLOCK_512:
      return 22;
    default:
      fprintf(stderr, "Invalid block size\n");
      exit(1);
  }
}

/* =========================================================
 * block_access: access block[row][col] in row-major order
 * ========================================================= */
unsigned char block_access(unsigned char *block, size_t row, size_t col,
                           aes_block_size_t block_size) {
  int cols = block_cols(block_size);
  return block[(row * cols) + col];
}

/* =========================================================
 * xtime: multiply a byte by 2 in GF(2^8)
 * Used internally by mix_columns
 * ========================================================= */
static unsigned char xtime(unsigned char a) {
  return (a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1);
}

/* =========================================================
 * Debug helper: print the block state as a 4xN grid
 * Only compiled in when DEBUG is defined.
 * ========================================================= */
#ifdef DEBUG
static void print_state(const char *label, unsigned char *block,
                        aes_block_size_t block_size) {
  int cols = block_cols(block_size);
  printf("[DEBUG] %s:\n", label);
  for (int r = 0; r < 4; r++) {
    for (int c = 0; c < cols; c++) {
      printf("%02x ", block[r * cols + c]);
    }
    printf("\n");
  }
  printf("\n");
}
#endif

/* =========================================================
 * SUB BYTES
 * Replace every byte in the block with its S-box value.
 * This provides non-linearity to the cipher.
 * ========================================================= */
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  size_t len = block_size_to_bytes(block_size);
  for (size_t i = 0; i < len; i++) {
    block[i] = sbox[block[i]];
  }
#ifdef DEBUG
  print_state("After sub_bytes", block, block_size);
#endif
}

/* =========================================================
 * SHIFT ROWS
 * Cyclically shift each row left by its row index.
 * Row 0: no shift, Row 1: shift 1, Row 2: shift 2, Row 3: shift 3
 * ========================================================= */
void shift_rows(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_cols(block_size);
  unsigned char temp[16]; /* max row width we need to handle */

  for (int r = 1; r < 4; r++) {
    /* copy row r into temp */
    for (int c = 0; c < cols; c++) {
      temp[c] = block[r * cols + c];
    }
    /* shift left by r positions */
    for (int c = 0; c < cols; c++) {
      block[r * cols + c] = temp[(c + r) % cols];
    }
  }
#ifdef DEBUG
  print_state("After shift_rows", block, block_size);
#endif
}

/* =========================================================
 * MIX COLUMNS
 * Each column is treated as a polynomial over GF(2^8)
 * and multiplied by a fixed polynomial.
 * This provides diffusion across the block.
 * ========================================================= */
void mix_columns(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_cols(block_size);

  for (int c = 0; c < cols; c++) {
    unsigned char s0 = block[0 * cols + c];
    unsigned char s1 = block[1 * cols + c];
    unsigned char s2 = block[2 * cols + c];
    unsigned char s3 = block[3 * cols + c];

    block[0 * cols + c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
    block[1 * cols + c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
    block[2 * cols + c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
    block[3 * cols + c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
  }
#ifdef DEBUG
  print_state("After mix_columns", block, block_size);
#endif
}

/* =========================================================
 * ADD ROUND KEY
 * XOR the block with the current round key.
 * This is the only step that uses the key directly.
 * ========================================================= */
void add_round_key(unsigned char *block, unsigned char *round_key,
                   aes_block_size_t block_size) {
  size_t len = block_size_to_bytes(block_size);
  for (size_t i = 0; i < len; i++) {
    block[i] ^= round_key[i];
  }
#ifdef DEBUG
  print_state("After add_round_key", block, block_size);
#endif
}

/* =========================================================
 * INVERT SUB BYTES
 * Replace every byte with its inverse S-box value.
 * Undoes sub_bytes during decryption.
 * ========================================================= */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  size_t len = block_size_to_bytes(block_size);
  for (size_t i = 0; i < len; i++) {
    block[i] = inv_sbox[block[i]];
  }
#ifdef DEBUG
  print_state("After invert_sub_bytes", block, block_size);
#endif
}

/* =========================================================
 * INVERT SHIFT ROWS
 * Cyclically shift each row RIGHT by its row index.
 * Undoes shift_rows during decryption.
 * ========================================================= */
void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_cols(block_size);
  unsigned char temp[16];

  for (int r = 1; r < 4; r++) {
    for (int c = 0; c < cols; c++) {
      temp[c] = block[r * cols + c];
    }
    /* shift right by r positions = shift left by (cols - r) */
    for (int c = 0; c < cols; c++) {
      block[r * cols + c] = temp[(c + cols - r) % cols];
    }
  }
#ifdef DEBUG
  print_state("After invert_shift_rows", block, block_size);
#endif
}

/* =========================================================
 * GF multiply helper for invert_mix_columns
 * Multiplies two bytes in GF(2^8)
 * ========================================================= */
static unsigned char gmul(unsigned char a, unsigned char b) {
  unsigned char p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    int hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1B;
    b >>= 1;
  }
  return p;
}

/* =========================================================
 * INVERT MIX COLUMNS
 * Applies the inverse MixColumns transformation.
 * Uses the inverse matrix with coefficients 0x0e, 0x0b, 0x0d, 0x09
 * ========================================================= */
void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_cols(block_size);

  for (int c = 0; c < cols; c++) {
    unsigned char s0 = block[0 * cols + c];
    unsigned char s1 = block[1 * cols + c];
    unsigned char s2 = block[2 * cols + c];
    unsigned char s3 = block[3 * cols + c];

    block[0 * cols + c] =
        gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
    block[1 * cols + c] =
        gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
    block[2 * cols + c] =
        gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
    block[3 * cols + c] =
        gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
  }
#ifdef DEBUG
  print_state("After invert_mix_columns", block, block_size);
#endif
}

/* =========================================================
 * EXPAND KEY
 * Takes a 16-byte cipher key and returns a 176-byte array
 * containing all 11 round keys for AES-128.
 *
 * For AES-256: 240 bytes (15 round keys)
 * For AES-512: extended similarly
 *
 * The key schedule works by deriving each new word from
 * the previous word and the word Nk positions before it.
 * ========================================================= */
unsigned char *expand_key(unsigned char *cipher_key,
                          aes_block_size_t block_size) {
  int cols = block_cols(block_size);
  int rounds = num_rounds(block_size);
  int key_len = block_size_to_bytes(block_size); /* key size = block size */
  int nk = cols;                                 /* words in original key */
  int total_words = cols * (rounds + 1);
  int expanded_len = total_words * 4;

  unsigned char *expanded = (unsigned char *)malloc(expanded_len);
  if (!expanded) {
    fprintf(stderr, "expand_key: malloc failed\n");
    exit(1);
  }

  /* Copy the original key as the first round key */
  memcpy(expanded, cipher_key, key_len);

  /* Generate remaining words */
  for (int i = nk; i < total_words; i++) {
    unsigned char temp[4];
    /* grab previous word */
    memcpy(temp, expanded + (i - 1) * 4, 4);

    if (i % nk == 0) {
      /* RotWord: rotate left by 1 byte */
      unsigned char t = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = t;

      /* SubWord: apply S-box to each byte */
      for (int j = 0; j < 4; j++) {
        temp[j] = sbox[temp[j]];
      }

      /* XOR with round constant */
      temp[0] ^= rcon[i / nk];
    } else if (nk > 6 && i % nk == 4) {
      /* Extra SubWord step for AES-256 and above */
      for (int j = 0; j < 4; j++) {
        temp[j] = sbox[temp[j]];
      }
    }

    /* XOR with word Nk positions earlier */
    for (int j = 0; j < 4; j++) {
      expanded[i * 4 + j] = expanded[(i - nk) * 4 + j] ^ temp[j];
    }
  }

  return expanded;
}

/* =========================================================
 * AES ENCRYPT BLOCK
 * Encrypts a single block of plaintext using AES.
 * Follows the standard 10/14/22 round structure:
 *   - Initial AddRoundKey
 *   - N-1 full rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey)
 *   - Final round (SubBytes, ShiftRows, AddRoundKey — no MixColumns)
 * ========================================================= */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key,
                                 aes_block_size_t block_size) {
  size_t len = block_size_to_bytes(block_size);
  int rounds = num_rounds(block_size);

  /* Allocate output and copy plaintext into it */
  unsigned char *output = (unsigned char *)malloc(len);
  if (!output) {
    fprintf(stderr, "aes_encrypt_block: malloc failed\n");
    exit(1);
  }
  memcpy(output, plaintext, len);

  /* Expand the key */
  unsigned char *round_keys = expand_key(key, block_size);

#ifdef DEBUG
  print_state("Initial plaintext", output, block_size);
#endif

  /* Initial round key addition */
  add_round_key(output, round_keys, block_size);

  /* Main rounds */
  for (int round = 1; round < rounds; round++) {
#ifdef DEBUG
    printf("[DEBUG] === Encrypt Round %d ===\n", round);
#endif
    sub_bytes(output, block_size);
    shift_rows(output, block_size);
    mix_columns(output, block_size);
    add_round_key(output, round_keys + round * len, block_size);
  }

  /* Final round (no MixColumns) */
#ifdef DEBUG
  printf("[DEBUG] === Encrypt Final Round ===\n");
#endif
  sub_bytes(output, block_size);
  shift_rows(output, block_size);
  add_round_key(output, round_keys + rounds * len, block_size);

  free(round_keys);
  return output;
}

/* =========================================================
 * AES DECRYPT BLOCK
 * Decrypts a single block of ciphertext using AES.
 * Follows the inverse round structure:
 *   - Initial AddRoundKey (with last round key)
 *   - N-1 full inverse rounds (InvShiftRows, InvSubBytes, AddRoundKey,
 * InvMixColumns)
 *   - Final inverse round (InvShiftRows, InvSubBytes, AddRoundKey)
 * ========================================================= */
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key,
                                 aes_block_size_t block_size) {
  size_t len = block_size_to_bytes(block_size);
  int rounds = num_rounds(block_size);

  /* Allocate output and copy ciphertext into it */
  unsigned char *output = (unsigned char *)malloc(len);
  if (!output) {
    fprintf(stderr, "aes_decrypt_block: malloc failed\n");
    exit(1);
  }
  memcpy(output, ciphertext, len);

  /* Expand the key */
  unsigned char *round_keys = expand_key(key, block_size);

#ifdef DEBUG
  print_state("Initial ciphertext", output, block_size);
#endif

  /* Initial round key addition with the LAST round key */
  add_round_key(output, round_keys + rounds * len, block_size);

  /* Main inverse rounds (going backwards) */
  for (int round = rounds - 1; round >= 1; round--) {
#ifdef DEBUG
    printf("[DEBUG] === Decrypt Round %d ===\n", round);
#endif
    invert_shift_rows(output, block_size);
    invert_sub_bytes(output, block_size);
    add_round_key(output, round_keys + round * len, block_size);
    invert_mix_columns(output, block_size);
  }

  /* Final inverse round (no InvMixColumns) */
#ifdef DEBUG
  printf("[DEBUG] === Decrypt Final Round ===\n");
#endif
  invert_shift_rows(output, block_size);
  invert_sub_bytes(output, block_size);
  add_round_key(output, round_keys, block_size);

  free(round_keys);
  return output;
}