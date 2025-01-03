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
#include <cstdio>
#include <string.h>

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

