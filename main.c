/*
  Darren Grants
  C21427252
  Rijndael (AES) implementation in C.
  Implements AES-128, AES-256, and AES-512 block encryption and decryption.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include "rijndael.h"
 
/* Default key used for all encryption/decryption */
static unsigned char default_key[16] = {50, 20, 46, 86, 67, 9,  70, 27,
                                         75, 17, 51, 17, 4,  8,  6,  99};
 
void print_block(unsigned char *block, aes_block_size_t block_size) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            unsigned char value = block_access(block, i, j, block_size);
            if (value < 10)  printf("  ");
            else if (value < 100) printf(" ");
            printf("%d ", value);
        }
        printf("\n");
    }
}
 
void print_hex(unsigned char *block, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", block[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    printf("\n");
}
 
void run_demo(unsigned char *plaintext) {
    printf("\n========== KEY ==========\n");
    print_hex(default_key, 16);
 
    printf("======= PLAINTEXT =======\n");
    print_block(plaintext, AES_BLOCK_128);
 
    unsigned char *ciphertext = aes_encrypt_block(plaintext, default_key, AES_BLOCK_128);
 
    printf("\n====== CIPHERTEXT (hex) ======\n");
    print_hex(ciphertext, 16);
 
    unsigned char *recovered = aes_decrypt_block(ciphertext, default_key, AES_BLOCK_128);
 
    printf("==== RECOVERED PLAINTEXT ====\n");
    print_block(recovered, AES_BLOCK_128);
 
    if (memcmp(plaintext, recovered, 16) == 0) {
        printf("\n[OK] Decryption matches original plaintext.\n");
    } else {
        printf("\n[FAIL] Decryption does not match!\n");
    }
 
    free(ciphertext);
    free(recovered);
}
 
int main() {
    int choice;
 
    printf("=================================\n");
    printf("   AES-128 Demo - Darren Grants\n");
    printf("=================================\n");
    printf("1. Use default plaintext\n");
    printf("2. Enter your own plaintext\n");
    printf("Choice: ");
    scanf("%d", &choice);
 
    if (choice == 1) {
        unsigned char plaintext[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                       9, 10, 11, 12, 13, 14, 15, 16};
        run_demo(plaintext);
 
    } else if (choice == 2) {
        char input[64];
        printf("Enter text (max 16 chars): ");
        scanf("%16s", input);
 
        /* Pad or truncate to exactly 16 bytes */
        unsigned char plaintext[16];
        memset(plaintext, 0, 16);
        memcpy(plaintext, input, strlen(input) < 16 ? strlen(input) : 16);
 
        run_demo(plaintext);
 
    } else {
        printf("Invalid choice.\n");
        return 1;
    }
 
    return 0;
}
