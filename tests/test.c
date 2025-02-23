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
#include <stdio.h>
#include "kem.h"
#include "utilities.h"
#include "measurements.h"
#include "hash_wrapper.h"
#include "FromNIST/rng.h"
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#ifdef _WIN32
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/resource.h>
    #include <sys/time.h>
#endif

// Cross-platform time measurement
#ifdef _WIN32
    #define CLOCK_TYPE LARGE_INTEGER
    #define GET_TIME(t) QueryPerformanceCounter(&t)
    #define GET_TIME_DIFF(end, start, freq) ((double)(end.QuadPart - start.QuadPart) / freq.QuadPart)
#else
    #define CLOCK_TYPE struct timespec
    #define GET_TIME(t) clock_gettime(CLOCK_MONOTONIC, &t)
    #define GET_TIME_DIFF(end, start, freq) \
        ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9)
#endif
// void print_memory_usage(FILE *fpt) {
//     struct rusage usage;
//     getrusage(RUSAGE_SELF, &usage);
//     //printf("Memory usage: %ld kilobytes\n", usage.ru_maxrss);
//     if (fpt != NULL) {
//         fprintf(fpt, "%ld,", usage.ru_maxrss);  // Write memory usage to CSV
//     }
// }
void print_memory_usage(FILE *fpt) {
    #ifdef _WIN32
        PROCESS_MEMORY_COUNTERS memCounter;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &memCounter, sizeof(memCounter))) {
            size_t mem_usage_kb = memCounter.WorkingSetSize / 1024;
            if (fpt != NULL) {
                fprintf(fpt, "%zu,", mem_usage_kb);
            } else {
                printf("Memory usage: %zu KB\n", mem_usage_kb);
            }
        } else {
            perror("Failed to get memory usage");
        }
    #else
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            if (fpt != NULL) {
                fprintf(fpt, "%ld,", usage.ru_maxrss);
            } else {
                printf("Memory usage: %ld kilobytes\n", usage.ru_maxrss);
            }
        } else {
            perror("Failed to get memory usage");
        }
    #endif
}

double get_amd_cpu_temp() {
    FILE *temp_file;
    char buffer[128];
    double temp = -1.0;
    
    // Search through hwmon devices for k10temp
    DIR *dir = opendir("/sys/class/hwmon");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            char name_path[256];
            snprintf(name_path, sizeof(name_path), "/sys/class/hwmon/%s/name", entry->d_name);
            
            FILE *name_file = fopen(name_path, "r");
            if (name_file) {
                char name[32];
                if (fgets(name, sizeof(name), name_file) != NULL) {
                    // Check if this is the AMD CPU temperature sensor
                    if (strstr(name, "k10temp")) {
                        char temp_path[256];
                        snprintf(temp_path, sizeof(temp_path), 
                                "/sys/class/hwmon/%s/temp1_input", entry->d_name);
                        
                        temp_file = fopen(temp_path, "r");
                        if (temp_file) {
                            if (fgets(buffer, sizeof(buffer), temp_file) != NULL) {
                                temp = atof(buffer) / 1000.0; // Convert from millidegrees to degrees
                            }
                            fclose(temp_file);
                        }
                    }
                }
                fclose(name_file);
            }
        }
        closedir(dir);
    }
    
    return temp;
}

int main(void)
{
    #ifdef _WIN32
        LARGE_INTEGER frequency;
        QueryPerformanceFrequency(&frequency);
    #endif
    CLOCK_TYPE start, end;
    sk_t sk = { 0 }; // private-key: (h0, h1)
    pk_t pk = { 0 }; // public-key:  (g0, g1)
    ct_t ct = { 0 }; // ciphertext:  (c0, c1)
    ss_t k_enc = { 0 }; // shared secret after encapsulate
    ss_t k_dec = { 0 }; // shared secret after decapsulate

//     const char* input1 = "The quick brown fox jumps over the lazy dog";
//     unsigned char output_openssl1[48ULL];
//     unsigned char output_new1[48ULL];
//     //sha3_384_openssl(output_openssl1, (const unsigned char*)input1, strlen(input1));

//     //Compute hash using new function
//     sha3_384(output_new1, (const unsigned char*)input1, strlen(input1));
    
//     //Compare results
//     if (memcmp(output_openssl1, output_new1, 48ULL) == 0) {
//         printf("SHA outputs match!\n");
//     } else {
//         printf("The outputs do not match.\n");
//     }
//     //Print the values of output_new1 and output_openssl1
//     printf("output_new1: ");
//     for (int i = 0; i < 48ULL; i++) {
//         printf("%02x", output_new1[i]);
//     }
//     printf("\n");

//     printf("output_openssl1: ");
//     for (int i = 0; i < 48ULL; i++) {
//         printf("%02x", output_openssl1[i]);
//     }
//     printf("\n");
    
//    unsigned char key[32] = {1, 2, 3, 4, 5, 6, 7, 8,
//                         9, 10, 11, 12, 13, 14, 15, 16,
//                         17, 18, 19, 20, 21, 22, 23, 24,
//                         25, 26, 27, 28, 29, 30, 31, 32};
// unsigned char input[16] = {'T','e','s','t','I','n','p','u',
//                           't','B','l','o','c','k','!','!'};  // Ensure 16 bytes exactly
// unsigned char output_openssl[16];
// unsigned char output_new[16];

// // Compute encrypted output using OpenSSL-based function
// AES256_ECB(key, input, output_openssl);

// // Compute encrypted output using new function
// //AES256_ECB_AES(key, input, output_new);

// // Print first output (16 bytes)
// printf("AES OpenSSL output: ");
// for (int i = 0; i < 16; i++) {
//     printf("%02x", output_openssl[i]);
// }
// printf("\n");

// // Print second output (16 bytes)
// printf("AES New implementation output: ");
// for (int i = 0; i < 16; i++) {
//     printf("%02x", output_new[i]);
// }
// printf("\n");

// // Compare results (16 bytes)
// if (memcmp(output_openssl, output_new, 16) == 0) {
//     printf("AES outputs match!\n");
// } else {
//     printf("The outputs do not match.\n");
// }

    MSG("BIKE Demo Test:\n");

    FILE *fpt = fopen("valuesNove.csv", "w+");
    if (fpt == NULL) {
        perror("Failed to open file");
        return 1;
    }

    fprintf(fpt, "KeyGen Time (s),KeyGen Memory (KB),Encaps Time (s),Encaps Memory (KB),Decaps Time (s),Decaps Memory (KB)\n");

    for (uint32_t i = 1; i <= NUM_OF_CODE_TESTS; ++i) {
        status_t res = SUCCESS;
        MSG("r: %d Code test: %d \n", (int)R_BITS, i);

        // Key generation
        GET_TIME(start);
        MEASURE("  keygen", res = static_cast<status_t>(crypto_kem_keypair(pk.raw, sk.raw)););
        GET_TIME(end);
        #ifdef _WIN32
            double time_taken = GET_TIME_DIFF(end, start, frequency);
        #else
            double time_taken = GET_TIME_DIFF(end, start, 0);
        #endif

        fprintf(fpt, "%f,", time_taken);
        print_memory_usage(fpt);

        printf("Clients private key ");
        for(size_t i = 0; i < 32; i++) {
            printf("%02x", sk.raw[i]);
        }
        printf("\n");

        if (res != SUCCESS) {
            MSG("Keypair failed with error: %d\n", res);
            continue;
        }

        for (uint32_t j = 1; j <= NUM_OF_ENCRYPTION_TESTS; ++j) {
            uint32_t dec_rc = 0;

            // Encapsulate
            GET_TIME(start);
            MEASURE("  encaps", res = static_cast<status_t>(crypto_kem_enc(ct.raw, k_enc.raw, pk.raw)););
            GET_TIME(end);
            double temp = get_amd_cpu_temp();
            if (temp > 0) {
                printf("AMD CPU Temperature: %.1f°C\n", temp);
            } else {
                printf("Could not read AMD CPU temperature\n");
            }
            #ifdef _WIN32
                time_taken = GET_TIME_DIFF(end, start, frequency);
            #else
                time_taken = GET_TIME_DIFF(end, start, 0);
            #endif

            fprintf(fpt, "%f,", time_taken);
            print_memory_usage(fpt);

            if (res != SUCCESS) {
                MSG("encapsulate failed with error: %d\n", res);
                continue;
            }

            // Decapsulate
            GET_TIME(start);
            MEASURE("  decaps", dec_rc = crypto_kem_dec(k_dec.raw, ct.raw, sk.raw););
            GET_TIME(end);

            #ifdef _WIN32
                time_taken = GET_TIME_DIFF(end, start, frequency);
            #else
                time_taken = GET_TIME_DIFF(end, start, 0);
            #endif

            fprintf(fpt, "%f,", time_taken);
            print_memory_usage(fpt);
            fprintf(fpt, "\n");

            if (dec_rc != 0) {
                MSG("Decoding failed after %d code tests and %d enc/dec tests!\n", i, j);
            } else {
                if (safe_cmp(k_enc.raw, k_dec.raw, sizeof(k_dec) / sizeof(uint64_t))) {
                    MSG("Success! decapsulated key is the same as encapsulated key!\n");
                } else {
                    MSG("Failure! decapsulated key is NOT the same as encapsulated key!\n");
                }
            }
        }
    }

    fclose(fpt);
    return 0;
}
