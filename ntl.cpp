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
#include <stdint.h>
#include <string.h>
#include <NTL/GF2X.h>
using namespace NTL;

typedef unsigned char uint8_t;

int get_degree(uint64_t a) {
    int degree = -1;

    while (a) {
        a >>= 1;
        degree++;
    }

    return degree;
}

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

    while (u != 1) { // u is instatly 1
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

//ntl_mod_inv()
//Main function to compute modular inverse without NTL
// void ntl_mod_inv(OUT uint8_t res_bin[R_SIZE], IN const uint8_t a_bin[R_SIZE]) {
//     uint64_t a = bin_to_uint64(a_bin);
//     uint64_t mod = (1ULL << R_BITS) | 1;
//     uint64_t inv = gf2_mod_inv(a, mod);
//     uint64_to_bin(inv, res_bin);
// }


// Your custom functions (slightly adjusted for clarity and consistency)
// uint64_t modular_exponentiation(uint64_t x, uint64_t y, uint64_t z) {
//     uint64_t res = 1;
//     x = x % z;
//     while (y > 0) {
//         if (y & 1)
//             res = (res * x) % z;
//         y = y >> 1;
//         x = (x * x) % z;
//     }
//     return res;
// }

// uint64_t moduloMultiplication(uint64_t a, uint64_t b, uint64_t z) {
//     uint64_t res = 0;
//     a %= z;
//     while (b) {
//         if (b & 1)
//             res = (res + a) % z;
//         a = (2 * a) % z; // Corrected 'p' to 'z'
//         b >>= 1;
//     }
//     return res;
// }

// void extendedEuclid(uint64_t A, uint64_t B, uint64_t* d, uint64_t* x, uint64_t* y) {
//     uint64_t temp;
//     if (B == 0) {
//         *d = A;
//         *x = 1;
//         *y = 0;
//     }
//     else {
//         extendedEuclid(B, A % B, d, y, &temp);
//         *x = *y;
//         *y = temp - (A / B) * *y;
//     }
// }

// int modInverse(uint64_t A, uint64_t M, uint64_t* x) {
//     uint64_t d, y;
//     extendedEuclid(A, M, &d, x, &y);
//     if (*x < 0)
//         *x += M;
//     return (*x!= 0); // Return success if inverse exists
// }

// //Function to convert byte array to uint64_t (simplified, assumes little-endian)
// uint64_t bytesToUint64_t(const uint8_t bytes[R_SIZE]) {
//     uint64_t result = 0;
//     for (int i = 0; i < R_SIZE; i++) {
//         result |= (uint64_t)bytes[i] << (8 * i);
//     }
//     return result;
// }

// void ntl_mod_inv(OUT uint8_t res_bin[R_SIZE],
//         IN const uint8_t a_bin[R_SIZE])
//  {
//     uint64_t a = bytesToUint64_t(a_bin);
//     uint64_t x;
//     uint64_t z = (1ULL << (R_BITS + 1)) | 1; // Example modulus, adjust as necessary
//     if (modInverse(a, z, &x)) {
//         // Convert result back to byte array (simplified, assumes little-endian)
//         for (int i = R_SIZE - 1; i >= 0; i--) {
//             res_bin[i] = x & 0xFF;
//             x >>= 8;
//         }
//     }
//      else {
//         // Handle case where inverse does not exist
//     }
// }

 void ntl_mod_inv(OUT uint8_t res_bin[R_SIZE],
        IN const uint8_t a_bin[R_SIZE])
{
    GF2X _m, a, res;

    GF2XFromBytes(a, a_bin, R_SIZE);

    //Create the modulus
    GF2XModulus m;
    SetCoeff(_m, 0, 1);
    SetCoeff(_m, R_BITS, 1);
    build(m, _m);
    InvMod(res, a, m);
    BytesFromGF2X(res_bin, res, R_SIZE);
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

