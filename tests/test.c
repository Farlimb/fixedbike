/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafaelmisoczki@google.com)
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
#include <time.h>
#include <sys/resource.h>
#include "stdio.h"
#include "kem.h"
#include "utilities.h"
#include "measurements.h"
#include "hash_wrapper.h"
#include "FromNIST/rng.h"
void print_memory_usage(FILE *fpt) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    //printf("Memory usage: %ld kilobytes\n", usage.ru_maxrss);
    if (fpt != NULL) {
        fprintf(fpt, "%ld,", usage.ru_maxrss);  // Write memory usage to CSV
    }
}

int main(void)
{
    struct timespec start, end;
    sk_t sk = { 0 }; // private-key: (h0, h1)
    pk_t pk = { 0 }; // public-key:  (g0, g1)
    ct_t ct = { 0 }; // ciphertext:  (c0, c1)
    ss_t k_enc = { 0 }; // shared secret after encapsulate
    ss_t k_dec = { 0 }; // shared secret after decapsulate

    const char* input1 = "The quick brown fox jumps over the lazy dog";
    unsigned char output_openssl1[48ULL];
    unsigned char output_new1[48ULL];
    //sha3_384_openssl(output_openssl1, (const unsigned char*)input1, strlen(input1));

    // Compute hash using new function
    //sha3_384(output_new1, (const unsigned char*)input1, strlen(input1));
    
    // Compare results
    // if (memcmp(output_openssl1, output_new1, 48ULL) == 0) {
    //     printf("The outputs match!\n");
    // } else {
    //     printf("The outputs do not match.\n");
    // }
// Print the values of output_new1 and output_openssl1
    // printf("output_new1: ");
    // for (int i = 0; i < 48ULL; i++) {
    //     printf("%02x", output_new1[i]);
    // }
    // printf("\n");

    // printf("output_openssl1: ");
    // for (int i = 0; i < 48ULL; i++) {
    //     printf("%02x", output_openssl1[i]);
    // }
    // printf("\n");
    
    unsigned char key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const unsigned char input[16] = "TestInputBlock!";
    unsigned char output_openssl[16];
    unsigned char output_new[16];

    // Compute encrypted output using OpenSSL-based function
    AES256_ECB(key, (unsigned char*)input, (unsigned char*)output_openssl);

    // Compute encrypted output using new function
    AES256_ECB_AES(key, (unsigned char*)input, (unsigned char*)output_new);

    // Compare results
    if (memcmp(output_openssl, output_new, 16) == 0) {
        printf("The outputs match!\n");
    } else {
        printf("The outputs do not match.\n");
    }

    MSG("BIKE Demo Test:\n");

    // Open the CSV file to write results
    FILE *fpt;
    fpt = fopen("values.csv", "w+");
    
    // Check if the file opened successfully
    if (fpt == NULL) {
        perror("Failed to open file");
        return 1; // Exit if the file can't be opened
    }
    
    // Write the headers to the CSV
    fprintf(fpt, "KeyGen Time (s),KeyGen Memory (KB),Encaps Time (s),Encaps Memory (KB),Decaps Time (s),Decaps Memory (KB)\n");

    for (uint32_t i = 1; i <= NUM_OF_CODE_TESTS; ++i)
    {
        status_t res = SUCCESS;
        MSG("r: %d Code test: %d \n", (int)R_BITS, i);

        // Key generation
        clock_gettime(CLOCK_MONOTONIC, &start);
        MEASURE("  keygen", res = static_cast<status_t>(crypto_kem_keypair(pk.raw, sk.raw)););
        clock_gettime(CLOCK_MONOTONIC, &end);   // End time
        double time_taken = (end.tv_sec - start.tv_sec) +
            (end.tv_nsec - start.tv_nsec) / 1e9; // Time in seconds
        //printf("Time taken: %f seconds for keygen\n", time_taken);
        fprintf(fpt, "%f,", time_taken);  // Write keygen time to CSV
        print_memory_usage(fpt);  // Write keygen memory usage to CSV

        if (res != SUCCESS)
        {
            MSG("Keypair failed with error: %d\n", res);
            continue;
        }

        for (uint32_t j = 1; j <= NUM_OF_ENCRYPTION_TESTS; ++j)
        {
            uint32_t dec_rc = 0;

            // Encapsulate
            clock_gettime(CLOCK_MONOTONIC, &start);
            MEASURE("  encaps", res = static_cast<status_t>(crypto_kem_enc(ct.raw, k_enc.raw, pk.raw)););
            clock_gettime(CLOCK_MONOTONIC, &end);   // End time
            time_taken = (end.tv_sec - start.tv_sec) +
                (end.tv_nsec - start.tv_nsec) / 1e9; // Time in seconds
            //printf("Time taken: %f seconds for encaps\n", time_taken);
            fprintf(fpt, "%f,", time_taken);  // Write encaps time to CSV
            print_memory_usage(fpt);  // Write encaps memory usage to CSV

            if (res != SUCCESS)
            {
                MSG("encapsulate failed with error: %d\n", res);
                continue;
            }

            // Decapsulate
            clock_gettime(CLOCK_MONOTONIC, &start);
            MEASURE("  decaps", dec_rc = crypto_kem_dec(k_dec.raw, ct.raw, sk.raw););
            clock_gettime(CLOCK_MONOTONIC, &end);   // End time
            time_taken = (end.tv_sec - start.tv_sec) +
                (end.tv_nsec - start.tv_nsec) / 1e9; // Time in seconds
            //printf("Time taken: %f seconds for decaps\n", time_taken);
            fprintf(fpt, "%f,", time_taken);  // Write decaps time to CSV
            print_memory_usage(fpt);  // Write decaps memory usage to CSV

            // Add a newline to end the row after all values for this cycle have been written
            fprintf(fpt, "\n");

            if (dec_rc != 0)
            {
                MSG("Decoding failed after %d code tests and %d enc/dec tests!\n", i, j);
            }
            else
            {
                if (safe_cmp(k_enc.raw, k_dec.raw, sizeof(k_dec) / sizeof(uint64_t)))
                {
                    MSG("Success! decapsulated key is the same as encapsulated key!\n");
                }
                else {
                    MSG("Failure! decapsulated key is NOT the same as encapsulated key!\n");
                }
            }
        }
    }

    // Close the CSV file
    fclose(fpt);

    return 0;
}
