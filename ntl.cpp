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

#include "types.h"
#include <string.h>

#define WORD_BITS 64
#define WORDS ((R_BITS + WORD_BITS - 1) / WORD_BITS)
#define MOD_WORD (R_BITS / WORD_BITS)
#define MOD_BIT (R_BITS % WORD_BITS)
#define MOD_MASK ((1ULL << MOD_BIT) - 1)

void ntl_mod_inv(uint8_t res_bin[R_SIZE], const uint8_t a_bin[R_SIZE]) {
    // Working buffers with optimal alignment
    alignas(32) uint64_t u[WORDS], v[WORDS], g1[WORDS], g2[WORDS];
    uint64_t *pu = u, *pv = v, *pg1 = g1, *pg2 = g2;

    // Initialize from input
    memset(pu, 0, sizeof(u));
    memcpy(pu, a_bin, R_SIZE);
    if (MOD_BIT) pu[MOD_WORD] &= MOD_MASK;

    // Initialize modulus (x^R_BITS + 1)
    memset(pv, 0, sizeof(v));
    pv[0] = 1;
    if (MOD_WORD < WORDS) pv[MOD_WORD] ^= 1ULL << MOD_BIT;

    // Initialize Bézout coefficients
    memset(pg1, 0, sizeof(g1));
    pg1[0] = 1;
    memset(pg2, 0, sizeof(g2));

    // Degree tracking
    int deg_u = -1, deg_v = -1;
    for (int i = WORDS-1; i >= 0; --i) {
        if (pu[i] && deg_u == -1) deg_u = i * WORD_BITS + 63 - __builtin_clzll(pu[i]);
        if (pv[i] && deg_v == -1) deg_v = i * WORD_BITS + 63 - __builtin_clzll(pv[i]);
    }

    while (deg_u > 0) {
        if (deg_u < deg_v) {
            // Swap pointers instead of arrays
            uint64_t *tmp;
            tmp = pu; pu = pv; pv = tmp;
            tmp = pg1; pg1 = pg2; pg2 = tmp;
            int t = deg_u; deg_u = deg_v; deg_v = t;
            continue;
        }

        const int shift = deg_u - deg_v;
        const int wshift = shift / WORD_BITS;
        const int bshift = shift % WORD_BITS;
        const int carry_shift = WORD_BITS - bshift;

        // Process words in reverse for better cache utilization
        for (int i = WORDS-1 - wshift; i >= 0; --i) {
            const int ti = i + wshift;
            const uint64_t v_val = pv[i];
            const uint64_t g_val = pg2[i];

            if (bshift) {
                pu[ti] ^= v_val << bshift;
                pg1[ti] ^= g_val << bshift;
                if (ti+1 < WORDS) {
                    pu[ti+1] ^= v_val >> carry_shift;
                    pg1[ti+1] ^= g_val >> carry_shift;
                }
            } else {
                pu[ti] ^= v_val;
                pg1[ti] ^= g_val;
            }
        }

        // Update degree using CLZ optimization
        deg_u = -1;
        for (int i = WORDS-1; i >= 0; --i) {
            if (pu[i]) {
                deg_u = i * WORD_BITS + 63 - __builtin_clzll(pu[i]);
                break;
            }
        }
    }

    // Final check and output
    if (pu[0] != 1) {
        memset(res_bin, 0, R_SIZE);
        return;
    }

    memcpy(res_bin, pg1, R_SIZE);
    if (MOD_BIT) res_bin[R_SIZE-1] &= (1U << (R_BITS % 8)) - 1;
}

void ntl_add(uint8_t res_bin[R_SIZE], const uint8_t a_bin[R_SIZE], const uint8_t b_bin[R_SIZE])
{
   for (size_t i = 0; i < R_SIZE; ++i) {
        res_bin[i] = a_bin[i] ^ b_bin[i];
    }
}

void ntl_mod_mul(uint8_t res_bin[R_SIZE], const uint8_t a_bin[R_SIZE], const uint8_t b_bin[R_SIZE]) {
    uint8_t result[2 * R_SIZE] = {0};

    // Polynomial multiplication over GF(2)
    for (int i = 0; i < R_SIZE * 8; i++) {
        if ((a_bin[i / 8] >> (i % 8)) & 1) {
            int shift_byte = i / 8;
            int shift_bit = i % 8;
            
            for (int j = 0; j < R_SIZE; j++) {
                uint8_t b_byte = b_bin[j];
                int target_byte = j + shift_byte;
                int carry_shift = 8 - shift_bit;

                // Handle main shift
                if (target_byte < 2 * R_SIZE) {
                    result[target_byte] ^= (b_byte << shift_bit);
                }

                // Handle carry-over bits
                if (shift_bit != 0 && target_byte + 1 < 2 * R_SIZE) {
                    result[target_byte + 1] ^= (b_byte >> carry_shift);
                }
            }
        }
    }

    // Modular reduction using x^R_BITS + 1
    const int modulus_bit = R_BITS;
    for (int i = 2 * R_SIZE * 8 - 1; i >= modulus_bit; i--) {
        int byte_pos = i / 8;
        int bit_pos = i % 8;
        
        if ((result[byte_pos] >> bit_pos) & 1) {
            // Clear current bit
            result[byte_pos] ^= (1 << bit_pos);
            
            // Toggle corresponding reduced bit
            int reduced_bit = i - modulus_bit;
            int red_byte = reduced_bit / 8;
            int red_bit = reduced_bit % 8;
            result[red_byte] ^= (1 << red_bit);
        }
    }

    memcpy(res_bin, result, R_SIZE);
}
 
void ntl_split_polynomial(uint8_t e0[R_SIZE],
                            uint8_t e1[R_SIZE],
                            const uint8_t e[2*R_SIZE]) {
    // Clear the outputs (if needed)
    memset(e0, 0, R_SIZE);
    memset(e1, 0, R_SIZE);

    // Compute how many whole bytes and extra bits we need to copy.
    int full_bytes = R_BITS / 8;
    int rem_bits   = R_BITS % 8;

    // --- Extract the first R_BITS bits into e0 ---
    // If we have full bytes, copy them directly.
    if (full_bytes > 0) {
        memcpy(e0, e, full_bytes);
    }
    // If there are remaining bits, copy and mask the last byte.
    if (rem_bits > 0) {
        e0[full_bytes] = e[full_bytes] & ((1 << rem_bits) - 1);
    }

    // Process the full bytes for e1.
    for (int i = 0; i < full_bytes; i++) {
        // If the starting bit is byte aligned, we can copy a full byte.
        if (rem_bits == 0) {
            e1[i] = e[full_bytes + i];
        } else {
            // Otherwise, the desired byte is split across two bytes in e.
            e1[i] = (e[full_bytes + i] >> rem_bits)
                    | (e[full_bytes + i + 1] << (8 - rem_bits));
        }
    }
    // Process any remaining bits (if R_BITS is not a multiple of 8).
    if (rem_bits > 0) {
            // Combine bits from the two adjacent bytes.
            uint16_t combined = (e[full_bytes + full_bytes] >> rem_bits)
                                | (e[full_bytes + full_bytes + 1] << (8 - rem_bits));
            e1[full_bytes] = combined & ((1 << rem_bits) - 1);
    }
}

// #include <NTL/GF2X.h>

// using namespace NTL;

// typedef unsigned char uint8_t;

// void ntl_add_openssl(OUT uint8_t res_bin[R_SIZE],
//         IN const uint8_t a_bin[R_SIZE],
//         IN const uint8_t b_bin[R_SIZE])
// {
//     GF2X a, b, res;

//     GF2XFromBytes(a, a_bin, R_SIZE);
//     GF2XFromBytes(b, b_bin, R_SIZE);

//     add(res, a, b);

//     BytesFromGF2X(res_bin, res, R_SIZE);
// }

// void ntl_mod_inv_openssl(OUT uint8_t res_bin[R_SIZE],
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

// void ntl_mod_mul_openssl(OUT uint8_t res_bin[R_SIZE],
//         IN const uint8_t a_bin[R_SIZE],
//         IN const uint8_t b_bin[R_SIZE])
// {
//     GF2X _m, a, b, res;

//     GF2XFromBytes(a, a_bin, R_SIZE);
//     GF2XFromBytes(b, b_bin, R_SIZE);

//     //Create the modulus
//     GF2XModulus m;
//     SetCoeff(_m, 0, 1);
//     SetCoeff(_m, R_BITS, 1);
//     build(m, _m);

//     MulMod(res, a, b, m);

//     BytesFromGF2X(res_bin, res, R_SIZE);
// }

// void ntl_split_polynomial_openssl(OUT uint8_t e0[R_SIZE],
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