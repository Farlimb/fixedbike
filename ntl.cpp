/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2021 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder,
 * Tim Gueneysu, Jan Richter-Brockmann.
 * Contact: drucker.nir@gmail.com, shay.gueron@gmail.com,
 * rafaelmisoczki@google.com, tobias.oder@rub.de, tim.gueneysu@rub.de,
 * jan.richter-brockmann@rub.de.
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

extern "C" {
#include "types.h"
}
//#include <gmp.h>
//#include <vector>
//#include <inttypes.h>
//#include <stdint.h>
#include <cstdio>
#include <string.h>
//#include <NTL/GF2X.h>
//using namespace NTL;

//typedef unsigned char uint8_t;

int get_degree(uint64_t a) {
    int degree = -1;

    while (a) {
        a >>= 1;
        degree++;
    }

    return degree;
}

// Function to perform polynomial division in GF(2) (returns quotient and remainder)
uint64_t gf2_div(uint64_t dividend, uint64_t divisor, uint64_t *remainder) {
    int deg_dividend = get_degree(dividend);
    int deg_divisor = get_degree(divisor);

    uint64_t quotient = 0;
    *remainder = dividend;

    while (deg_dividend >= deg_divisor) {
        int shift = deg_dividend - deg_divisor;
        quotient ^= (1ULL << shift);
        *remainder ^= (divisor << shift);
        deg_dividend = get_degree(*remainder);
    }
    return quotient;
}

// Function to compute the modular inverse using Extended Euclidean Algorithm
uint64_t gf2_mod_inv(uint64_t a, uint64_t mod) {
    uint64_t u = a, v = mod;
    uint64_t g1 = 1, g2 = 0;

    while (u != 1) {
        uint64_t remainder;
        uint64_t q = gf2_div(u, v, &remainder);
        u = v;
        v = remainder;

        uint64_t tmp = g2 ^ gf2_div(q, mod, &remainder) ^ g1;
        g1 = g2;
        g2 = tmp;
    }

    return g1;
}

// Function to convert binary array to uint64_t (polynomial form)
uint64_t bin_to_uint64(const uint8_t bin[R_SIZE]) {
    uint64_t result = 0;

    for (size_t i = 0; i < R_SIZE; i++) {
        result |= ((uint64_t)bin[i]) << (i * 8);
    }
    return result;
}

// Function to convert uint64_t to binary array
void uint64_to_bin(uint64_t value, uint8_t bin[R_SIZE]) {
    for (size_t i = 0; i < R_SIZE; i++) {
        bin[i] = (value >> (i * 8)) & 0xFF;
    }
}
static inline void set_bit(uint8_t* array, size_t bit_index) {
    array[bit_index / 8] |= (1 << (bit_index % 8));
}
// ntl_mod_inv()
// Main function to compute modular inverse without NTL
// void ntl_mod_inv_mine(OUT uint8_t res_bin[R_SIZE], IN const uint8_t a_bin[R_SIZE]) {
//      uint64_t a = bin_to_uint64(a_bin);
//      uint8_t v[R_SIZE] = {0};
//      set_bit(v, 0);
//      set_bit(v, R_BITS);
//      unsigned long long mod = bin_to_uint64(v);;
//      uint64_t inv = gf2_mod_inv(a, mod);
//      uint64_to_bin(inv, res_bin);
// }



static inline int get_bit(const uint8_t* array, size_t bit_index) {
    return (array[bit_index / 8] >> (bit_index % 8)) & 1;
}

// Extended Euclidean Algorithm for polynomials over GF(2)
#define MASK_TOP_BIT(x) ((x) & 0x7f)

void print_hex(const uint8_t* data, size_t len) {
    for(size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void poly_gf2_extended_euclidean(uint8_t* result, const uint8_t* a, size_t size_bytes) {
    if (size_bytes != R_SIZE) {
        printf("Error: Invalid size_bytes %zu, expected %zu\n", size_bytes, (size_t)R_SIZE);
        return;
    }

    // Print input for debugging
    printf("Input polynomial: ");
    print_hex(a, size_bytes);

    uint8_t u[R_SIZE] = {0};
    uint8_t v[R_SIZE] = {0};
    uint8_t g1[R_SIZE] = {0};
    uint8_t g2[R_SIZE] = {0};
    uint8_t temp[R_SIZE] = {0};

    // Copy input polynomial
    memcpy(u, a, size_bytes);

    // Initialize modulus polynomial (x^R_BITS + 1)
    set_bit(v, 0);
    set_bit(v, R_BITS);

    // Initialize g1 = 1
    set_bit(g1, 0);

    int iteration = 0;
    while (iteration < 100000) { // Add iteration limit for safety
        int deg_u = R_BITS;
        int deg_v = R_BITS;

        while (deg_u >= 0 && !get_bit(u, deg_u)) deg_u--;
        while (deg_v >= 0 && !get_bit(v, deg_v)) deg_v--;

        printf("Iteration %d: deg_u = %d, deg_v = %d\n", iteration, deg_u, deg_v);

        if (deg_v == -1) {
            printf("Found inverse. Result: ");
            memcpy(result, g1, size_bytes);
            print_hex(result, size_bytes);
            return;
        }

        while (deg_u >= deg_v && deg_u >= 0) {
            if (get_bit(u, deg_u)) {
                // Perform polynomial reduction
                int shift = deg_u - deg_v;
                
                // u += v << shift
                for (int i = 0; i <= deg_v; i++) {
                    if (get_bit(v, i)) {
                        int target_bit = i + shift;
                        if (target_bit < R_BITS) {
                            u[target_bit / 8] ^= (1 << (target_bit % 8));
                        }
                    }
                }

                // g1 += g2 << shift
                for (int i = 0; i < R_BITS; i++) {
                    if (get_bit(g2, i)) {
                        int target_bit = i + shift;
                        if (target_bit < R_BITS) {
                            g1[target_bit / 8] ^= (1 << (target_bit % 8));
                        }
                    }
                }
            }
            deg_u--;
        }

        // Swap u and v
        memcpy(temp, u, size_bytes);
        memcpy(u, v, size_bytes);
        memcpy(v, temp, size_bytes);

        // Swap g1 and g2
        memcpy(temp, g1, size_bytes);
        memcpy(g1, g2, size_bytes);
        memcpy(g2, temp, size_bytes);

        iteration++;
    }

    printf("Error: Maximum iterations reached\n");
}

void local_mod_inv(OUT uint8_t res_bin[R_SIZE],
                   IN const uint8_t a_bin[R_SIZE]) {
    printf("Starting local_mod_inv with R_SIZE = %zu\n", (size_t)R_SIZE);
    poly_gf2_extended_euclidean(res_bin, a_bin, R_SIZE);
}

// void ntl_mod_inv(OUT uint8_t res_bin[R_SIZE], IN const uint8_t a_bin[R_SIZE]) {
//     // Convert input to polynomial
//     GF2Poly a = GF2Poly::from_bytes(a_bin, R_SIZE);
    
//     // Create modulus polynomial (x^R_BITS + 1)
//     GF2Poly modulus(R_BITS + 1);
//     modulus.set_coeff(0, true);        // x^0
//     modulus.set_coeff(R_BITS, true);   // x^R_BITS
    
//     // Compute modular inverse
//     GF2Poly result = extended_gcd(a, modulus, R_BITS + 1);
    
//     // Convert result back to bytes
//     result.to_bytes(res_bin, R_SIZE);
// }
// void ntl_mod_inv(OUT uint8_t res_bin[R_SIZE],
//         IN const uint8_t a_bin[R_SIZE])
// {
//     GF2X _m, a, res;

//     GF2XFromBytes(a, a_bin, R_SIZE);

//     //Create the modulus
//     GF2XModulus m;
//     SetCoeff(_m, 0, 1);
//     SetCoeff(_m, R_BITS, 1);
//     build(m, _m);

//     InvMod(res, a, m);
//     BytesFromGF2X(res_bin, res, R_SIZE);
// }

void ntl_mod_inv(OUT uint8_t res_bin[R_SIZE], IN const uint8_t a_bin[R_SIZE]) {
    const size_t WORDS = (R_BITS + 63) / 64;
    
    // Use aligned memory for better performance
    alignas(32) uint64_t a[WORDS] = {0};
    alignas(32) uint64_t m[WORDS] = {0};
    alignas(32) uint64_t u[WORDS] = {0};
    alignas(32) uint64_t v[WORDS] = {0};
    alignas(32) uint64_t g1[WORDS] = {0};
    alignas(32) uint64_t g2[WORDS] = {0};

    // Fast byte to word conversion using unaligned loads
    #pragma GCC unroll 8
    for(size_t i = 0; i < (R_SIZE + 7) / 8; i++) {
        uint64_t word = 0;
        size_t remaining_bytes = (i * 8 + 8 <= R_SIZE) ? 8 : R_SIZE - i * 8;
        memcpy(&word, a_bin + i * 8, remaining_bytes);
        a[i] = word;
    }

    // Set up modulus (x^R_BITS + 1)
    m[0] = 1;
    m[R_BITS/64] |= 1ULL << (R_BITS % 64);

    // Initialize working variables
    memcpy(u, a, sizeof(uint64_t) * WORDS);
    memcpy(v, m, sizeof(uint64_t) * WORDS);
    g1[0] = 1;

    // Precompute masks for performance
    const uint64_t WORD_MASK = (uint64_t)-1;
    
    while(1) {
        // Find degrees using __builtin_clzll with branch prediction hints
        int deg_u = -1;
        int deg_v = -1;
        
        // Find degree of u
        #pragma GCC unroll 4
        for(int i = WORDS-1; i >= 0; i--) {
            if(__builtin_expect(u[i] != 0, 0)) {
                deg_u = i * 64 + 63 - __builtin_clzll(u[i]);
                break;
            }
        }

        if(__builtin_expect(deg_u == 0, 0)) break;

        // Find degree of v
        #pragma GCC unroll 4
        for(int i = WORDS-1; i >= 0; i--) {
            if(__builtin_expect(v[i] != 0, 0)) {
                deg_v = i * 64 + 63 - __builtin_clzll(v[i]);
                break;
            }
        }

        // Conditional swap using XOR - eliminates branches
        if(deg_u < deg_v) {
            #pragma GCC unroll 4
            for(size_t i = 0; i < WORDS; i++) {
                uint64_t tmp;
                tmp = u[i] ^ v[i];
                u[i] ^= tmp;
                v[i] ^= tmp;
                
                tmp = g1[i] ^ g2[i];
                g1[i] ^= tmp;
                g2[i] ^= tmp;
            }
            continue;
        }

        const int shift = deg_u - deg_v;
        const size_t word_shift = shift / 64;
        const size_t bit_shift = shift % 64;
        const size_t inv_bit_shift = 64 - bit_shift;

        // Optimized shifting using SIMD instructions if available
        #pragma GCC unroll 4
        for(size_t i = 0; i < WORDS - word_shift; i++) {
            uint64_t v_shifted = (bit_shift == 0) ? 
                v[i] : 
                (v[i] << bit_shift) | ((i > 0) ? (v[i-1] >> inv_bit_shift) : 0);
                
            uint64_t g2_shifted = (bit_shift == 0) ? 
                g2[i] : 
                (g2[i] << bit_shift) | ((i > 0) ? (g2[i-1] >> inv_bit_shift) : 0);

            u[i + word_shift] ^= v_shifted;
            g1[i + word_shift] ^= g2_shifted;
        }
    }

    // Fast word to byte conversion using unaligned stores
    #pragma GCC unroll 8
    for(size_t i = 0; i < (R_SIZE + 7) / 8; i++) {
        uint64_t word = g1[i];
        size_t remaining_bytes = (i * 8 + 8 <= R_SIZE) ? 8 : R_SIZE - i * 8;
        memcpy(res_bin + i * 8, &word, remaining_bytes);
    }
}

// void ntl_mod_inv(OUT uint8_t res_bin[R_SIZE],
//         IN const uint8_t a_bin[R_SIZE])
// {
//     uint8_t a_bin_copy[R_SIZE];
//     uint8_t res_bin_copy[R_SIZE];
//     memcpy(a_bin_copy, a_bin, R_SIZE);
//     memcpy(res_bin_copy, res_bin, R_SIZE);
//     if(memcmp(res_bin_copy, res_bin, R_SIZE) != 0) {
//         printf("Error\n");
//     }
//     if(memcmp(a_bin_copy, a_bin, R_SIZE)  != 0){
//         printf("Error\n");
//     }
//     ntl_mod_inv_mine(res_bin_copy, a_bin_copy);
//     GF2X _m, a, res;

//     GF2XFromBytes(a, a_bin, R_SIZE);

//     //Create the modulus
//     GF2XModulus m;
//     SetCoeff(_m, 0, 1);
//     SetCoeff(_m, R_BITS, 1);
//     build(m, _m);
//     InvMod(res, a, m);
//     BytesFromGF2X(res_bin, res, R_SIZE);
//     if(memcmp(res_bin_copy, res_bin, R_SIZE) != 0) {
//         printf("Error\n");
//     }
    
//     bin_to_uint64(res_bin);
//     bin_to_uint64(res_bin_copy);
//     printf("%" PRIu64 "\n", res_bin);
//     printf("%" PRIu64, res_bin_copy);
// }

void ntl_add(uint8_t res_bin[R_SIZE], const uint8_t a_bin[R_SIZE], const uint8_t b_bin[R_SIZE])
{
   for (size_t i = 0; i < R_SIZE; ++i) {
        res_bin[i] = a_bin[i] ^ b_bin[i];
    }
}

 void ntl_mod_mul(uint8_t res_bin[R_SIZE], const uint8_t a_bin[R_SIZE], const uint8_t b_bin[R_SIZE]) {
     uint8_t result[2 * R_SIZE] = {0};
     uint8_t modulus[R_SIZE] = {0};
     modulus[0] = 1;
     modulus[R_BITS / 8] = 1 << (R_BITS % 8);

     // Polynomial multiplication over GF(2)
     for (int i = 0; i < R_SIZE * 8; i++) {
         if ((a_bin[i / 8] >> (i % 8)) & 1) {
             for (int j = 0; j < R_SIZE * 8; j++) {
                 if ((b_bin[j / 8] >> (j % 8)) & 1) {
                     result[(i + j) / 8] ^= (1 << ((i + j) % 8));
                 }
             }
         }
     }

     // Modular reduction
     for (int i = (2 * R_SIZE * 8) - 1; i >= R_BITS; i--) {
         if ((result[i / 8] >> (i % 8)) & 1) {
             int shift = i - R_BITS;
             for (int j = 0; j < R_SIZE * 8; j++) {
                 if ((modulus[j / 8] >> (j % 8)) & 1) {
                     result[(j + shift) / 8] ^= (1 << ((j + shift) % 8));
                 }
             }
         }
     }

     memcpy(res_bin, result, R_SIZE);
 }
 
void ntl_split_polynomial(uint8_t e0[R_SIZE], uint8_t e1[R_SIZE], const uint8_t e[2*R_SIZE]) {
    // Iterate over the input bytes
    int bit_offset = 0;
    for (int i = 0; i < 2*R_SIZE; i++) {
        // Process the current byte
        uint8_t byte = e[i];
        for (int j = 0; j < 8; j++) {
            // Check if the current bit is within the lower R_BITS bits
            if (bit_offset < R_BITS) {
                // Set the corresponding bit in e0
                e0[bit_offset / 8] |= (byte & (1 << j)) >> j << (bit_offset % 8);
            }
            // Check if the current bit is within the upper R_BITS bits
            if (bit_offset >= R_BITS && bit_offset < 2 * R_BITS) {
                // Set the corresponding bit in e1
                e1[(bit_offset - R_BITS) / 8] |= (byte & (1 << j)) >> j << ((bit_offset - R_BITS) % 8);
            }
            bit_offset++;
        }
    }
}

// void ntl_split_polynomial(OUT uint8_t e0[R_SIZE],
//         OUT uint8_t e1[R_SIZE],
//         IN const uint8_t e[2*R_SIZE])
// {
//     GF2X e_pol, e0_pol, e1_pol;
//     GF2XFromBytes(e_pol, e, N_SIZE);
//     trunc(e0_pol, e_pol, R_BITS);
//     RightShift(e1_pol, e_pol, R_BITS);

//     BytesFromGF2X(e0, e0_pol, R_SIZE);
//     BytesFromGF2X(e1, e1_pol, R_SIZE);
// }

