#include "stdio.h"
#include "kem.h"
#include "utilities.h"
#include "measurements.h"
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "hash_wrapper.h"
#include "openssl_utils.h"
#include "ntl.h"
#include "decode.h"
#include "sampling.h"
#include "conversions.h"
#include "shake_prng.h"
/////////////////////
//For testing you need to uncomment the commented code in ntl.cpp, hash_wrapper.c, rng.c
////////////////////

// Helper function to print byte arrays
void print_bytes(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 30; i++) { // Print first 16 bytes max
        printf("%02x ", data[i]);
    }
    if (len > 16) printf("...");
    printf("\n");
}

// Function to compare split_polynomial implementations
void compare_split_polynomial(const uint8_t *e) {
    uint8_t e0_custom[R_SIZE] = {0};
    uint8_t e1_custom[R_SIZE] = {0};
    uint8_t e0_openssl[R_SIZE] = {0};
    uint8_t e1_openssl[R_SIZE] = {0};
    print_bytes("Vstup e", e, R_SIZE);
    // Run both implementations
    ntl_split_polynomial(e0_custom, e1_custom, e);
    ntl_split_polynomial_openssl(e0_openssl, e1_openssl, e);
    
    // Print outputs
    print_bytes("Vlastna implementacia e0", e0_custom, R_SIZE);
    print_bytes("NTL implementacia e0    ", e0_openssl, R_SIZE);
    print_bytes("Vlastna implementacia e1", e1_custom, R_SIZE);
    print_bytes("NTL implementacia e1    ", e1_openssl, R_SIZE);
    
    // Compare results
    int match_e0 = (memcmp(e0_custom, e0_openssl, R_SIZE) == 0);
    int match_e1 = (memcmp(e1_custom, e1_openssl, R_SIZE) == 0);
    
    printf("ntl_split_polynomial porovnanie:\n");
    printf("  e0: %s\n", match_e0 ? "ZHODA" : "ROZDIELNE");
    printf("  e1: %s\n", match_e1 ? "ZHODA" : "ROZDIELNE");
    
    if (!match_e0) {
        printf("  e0 differences (first 10 bytes):\n");
        for (int i = 0; i < 10 && i < R_SIZE; i++) {
            if (e0_custom[i] != e0_openssl[i]) {
                printf("    Byte %d: %02x vs %02x\n", i, e0_custom[i], e0_openssl[i]);
            }
        }
    }
    
    if (!match_e1) {
        printf("  e1 differences (first 10 bytes):\n");
        for (int i = 0; i < 10 && i < R_SIZE; i++) {
            if (e1_custom[i] != e1_openssl[i]) {
                printf("    Byte %d: %02x vs %02x\n", i, e1_custom[i], e1_openssl[i]);
            }
        }
    }
}

// Function to compare add implementations
void compare_add(const uint8_t *a, const uint8_t *b) {
    uint8_t res_custom[R_SIZE] = {0};
    uint8_t res_openssl[R_SIZE] = {0};
    
    ntl_add(res_custom, a, b);
    ntl_add_openssl(res_openssl, a, b);
    
    // Print outputs
    print_bytes("Vlastna implementacia add", res_custom, R_SIZE);
    print_bytes("NTL implementacia add    ", res_openssl, R_SIZE);
    
    int match = (memcmp(res_custom, res_openssl, R_SIZE) == 0);
    printf("ntl_add porovnanie: %s\n", match ? "ZHODA" : "ROZDIELNE");
    
    if (!match) {
        printf("  Differences (first 10 bytes):\n");
        for (int i = 0; i < 10 && i < R_SIZE; i++) {
            if (res_custom[i] != res_openssl[i]) {
                printf("    Byte %d: %02x vs %02x\n", i, res_custom[i], res_openssl[i]);
            }
        }
    }
}

// Function to compare mod_mul implementations
void compare_mod_mul(const uint8_t *a, const uint8_t *b) {
    uint8_t res_custom[R_SIZE] = {0};
    uint8_t res_openssl[R_SIZE] = {0};
    print_bytes("Vstup a", a, R_SIZE);
    print_bytes("Vstup b", b, R_SIZE);
    ntl_mod_mul(res_custom, a, b);
    ntl_mod_mul_openssl(res_openssl, a, b);
    
    // Print outputs
    print_bytes("Vlastna implementacia mod_mul", res_custom, R_SIZE);
    print_bytes("NTL implementacia mod_mul    ", res_openssl, R_SIZE);
    
    int match = (memcmp(res_custom, res_openssl, R_SIZE) == 0);
    printf("ntl_mod_mul porovnanie: %s\n", match ? "ZHODA" : "ROZDIELNE");
    
    if (!match) {
        printf("  Differences (first 10 bytes):\n");
        for (int i = 0; i < 10 && i < R_SIZE; i++) {
            if (res_custom[i] != res_openssl[i]) {
                printf("    Byte %d: %02x vs %02x\n", i, res_custom[i], res_openssl[i]);
            }
        }
    }
}

// Function to compare mod_inv implementations
void compare_mod_inv(const uint8_t *a) {
    uint8_t res_custom[R_SIZE] = {0};
    uint8_t res_openssl[R_SIZE] = {0};
    
    // Print input
    print_bytes("Mod Inv vstup", a, R_SIZE);
    
    ntl_mod_inv(res_custom, a);
    ntl_mod_inv_openssl(res_openssl, a);
    
    // Print outputs
    print_bytes("Vlastna implementacia mod_inv", res_custom, R_SIZE);
    print_bytes("NTL implementacia mod_inv    ", res_openssl, R_SIZE);
    
    int match = (memcmp(res_custom, res_openssl, R_SIZE) == 0);
    printf("ntl_mod_inv porovnanie: %s\n", match ? "ZHODA" : "ROZDIELNE");
    
    if (!match) {
        printf("  Differences (first 10 bytes):\n");
        for (int i = 0; i < 10 && i < R_SIZE; i++) {
            if (res_custom[i] != res_openssl[i]) {
                printf("    Byte %d: %02x vs %02x\n", i, res_custom[i], res_openssl[i]);
            }
        }
    }
    
    // Verification: Multiply by original and check if result is 1
    uint8_t verify_custom[R_SIZE] = {0};
    uint8_t verify_openssl[R_SIZE] = {0};
    uint8_t one[R_SIZE] = {0};
    one[0] = 1; // Set first byte to 1, rest are 0
    
    ntl_mod_mul(verify_custom, a, res_custom);
    ntl_mod_mul_openssl(verify_openssl, a, res_openssl);
}

int main() {
    printf("Starting tests\n");
    sk_t sk = { 0 }; // private-key: (h0, h1)
    pk_t pk = { 0 }; // public-key:  (g0, g1)
    ct_t ct = { 0 }; // ciphertext:  (c0, c1)
    ss_t k_enc = { 0 }; // shared secret after encapsulate
    ss_t k_dec = { 0 }; // shared secret after decapsulate
    
    const char* input1 = "The quick brown fox jumps over the lazy dog";
    unsigned char output_openssl1[48ULL];
    unsigned char output_new1[48ULL];
    sha3_384_openssl(output_openssl1, (const unsigned char*)input1, strlen(input1));
    
    //Compute hash using new function
    sha3_384(output_new1, (const unsigned char*)input1, strlen(input1));
        
    //Print the values of output_new1 and output_openssl1
    printf("SHA vlastna implementacia vystup: ");
    for (int i = 0; i < 48ULL; i++) {
        printf("%02x", output_new1[i]);
    }
    printf("\n");
    
    printf("SHA OpenSSL vystup: ");
    for (int i = 0; i < 48ULL; i++) {
        printf("%02x", output_openssl1[i]);
    }
    printf("\n");
    
    if (memcmp(output_openssl1, output_new1, 48ULL) == 0) {
        printf("Vysledky SHA3_384 hashovani su zhodne!\n");
    } else {
        printf("Vysledky SHA3_384 hashovani nie su zhodne!\n");
    }
    unsigned char key[32] = {1, 2, 3, 4, 5, 6, 7, 8,
                            9, 10, 11, 12, 13, 14, 15, 16,
                            17, 18, 19, 20, 21, 22, 23, 24,
                            25, 26, 27, 28, 29, 30, 31, 32};
    unsigned char input[16] = {'T','e','s','t','I','n','p','u',
                              't','B','l','o','c','k','!','!'};  // Ensure 16 bytes exactly
    unsigned char output_openssl[16];
    unsigned char output_new[16];
    
    // Compute encrypted output using OpenSSL-based function
    AES256_ECB(key, input, output_openssl);
    
    // Compute encrypted output using new function
    AES256_ECB_AES(key, input, output_new);
    
    // Print first output (16 bytes)
    printf("AES OpenSSL vystup : ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", output_openssl[i]);
    }
    printf("\n");
    
    // Print second output (16 bytes)
    printf("AES vlastna implementancia vystup: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", output_new[i]);
    }
    printf("\n");
    
    // Compare results (16 bytes)
    if (memcmp(output_openssl, output_new, 16) == 0) {
        printf("Vysledky AES sifrovani su zhodne!\n");
    } else {
        printf("Vysledky AES sifrovani nie su zhodne!\n");
    }
    sk_t sk_check = {0};
    pk_t pk_check = {0};
    
    int result = crypto_kem_keypair(pk_check.raw, sk_check.raw);
    
    if (result != 0) {
        printf("Key generation failed with error: %d\n", result);
        return 1;
    }
    
    printf("Key pair generated successfully\n");
    
    uint8_t *h0 = sk_check.val0;
    uint8_t *h1 = sk_check.val1;
    
    uint8_t combined[2*R_SIZE] = {0};
    memcpy(combined, h0, R_SIZE);
    memcpy(combined + R_SIZE, h1, R_SIZE);
    
    printf("\n======= TESTOVANIE =======\n");
    
    // Test add
    printf("\n----- Testovanie Add -----\n");
    print_bytes("Vstup a (h0)", h0, R_SIZE);
    print_bytes("Vstup b (h1)", h1, R_SIZE);
    compare_add(h0, h1);
    
    // Test mod_mul
    printf("\n----- Testovanie Mod Mul -----\n");
    compare_mod_mul(h0, h1);
    
    // Test mod_inv
    printf("\n----- Testovanie Mod Inv -----\n");
    compare_mod_inv(h0);
    
    // Test split_polynomial
    printf("\n----- Testovanie Split Polynomial -----\n");
    compare_split_polynomial(combined);
    
    printf("\n=========================================\n");
    
    return 0;
}