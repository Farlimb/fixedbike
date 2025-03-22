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
#include <sys/io.h>
#include <math.h>
#include <x86intrin.h>
#include <stdint.h>
#include <sys/stat.h>
#include <limits.h>
#include <pthread.h>

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
// Function to generate random bytes from temperature readings



void create_test_directory() {
    const char* dir_name = "random_test_files";
    mkdir(dir_name, 0777);  // Read/write for all

    char abs_path[PATH_MAX];
    if (realpath(dir_name, abs_path) != NULL) {
        printf("Test files will be saved in: %s\n", abs_path);
    }
}

typedef struct {
    uint64_t raw_value;
    uint64_t microseconds;
    double temp;
} temp_data;

static inline uint64_t get_microseconds() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

// Function to get temperature reading
temp_data get_temp_reading() {
    temp_data reading = {0};
    FILE *fp;
    char buffer[128];
    
    reading.microseconds = get_microseconds();
    
    fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            reading.raw_value = strtoull(buffer, NULL, 10);
            reading.temp = (double)reading.raw_value / 1000.0;
        }
        fclose(fp);
    }
    
    return reading;
}

// Function to generate random bytes from temperature readings
void generate_random_file(const char* filename, size_t num_bytes) {
    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "random_test_files/%s", filename);
    
    FILE* output = fopen(filepath, "wb");
    if (!output) {
        fprintf(stderr, "Cannot open output file: %s\n", filepath);
        return;
    }
    
    unsigned char byte = 0;
    temp_data prev = get_temp_reading();
    
    for (size_t i = 0; i < num_bytes; i++) {
        temp_data current = get_temp_reading();
        
        // Get various sources of entropy
        uint64_t temp_delta = current.raw_value - prev.raw_value;
        uint64_t time_delta = current.microseconds - prev.microseconds;
        uint64_t cycles = __rdtsc();
        
        // Combine entropy sources
        unsigned char entropy_bytes[8];
        memcpy(entropy_bytes, &temp_delta, sizeof(temp_delta));
        memcpy(entropy_bytes + 4, &time_delta, sizeof(uint32_t));
        
        // XOR with CPU cycles
        for (int j = 0; j < 8; j++) {
            entropy_bytes[j] ^= (cycles >> (j * 8)) & 0xFF;
        }
        
        // Additional mixing
        entropy_bytes[i % 8] = (entropy_bytes[i % 8] << 3) | (entropy_bytes[i % 8] >> 5);
        
        // Write byte to file
        fwrite(&entropy_bytes[i % 8], 1, 1, output);
        
        prev = current;
        usleep(10); // Small delay to allow temperature to vary
    }
    
    fclose(output);
    printf("Generated %zu bytes of random data in %s\n", num_bytes, filepath);
}

// Enhanced random byte generation
unsigned char get_enhanced_random_byte() {
    temp_data reading = get_temp_reading();
    uint64_t cycles = __rdtsc();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    // Combine multiple entropy sources
    unsigned char byte = 0;
    byte ^= (reading.raw_value & 0xFF);
    byte ^= ((cycles >> 32) & 0xFF);
    byte ^= ((cycles) & 0xFF);
    byte ^= (ts.tv_nsec & 0xFF);
    
    // Additional mixing
    byte = (byte << 3) | (byte >> 5); // Rotate
    byte ^= (reading.microseconds & 0xFF);
    
    return byte;
}

// Modify generate_enhanced_random_file to use the directory
void generate_enhanced_random_file(const char* filename, size_t num_bytes) {
    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "random_test_files/%s", filename);
    
    FILE* output = fopen(filepath, "wb");
    if (!output) {
        fprintf(stderr, "Cannot open output file: %s\n", filepath);
        return;
    }
    
    unsigned char buffer[4096];
    size_t bytes_remaining = num_bytes;
    
    while (bytes_remaining > 0) {
        size_t chunk_size = (bytes_remaining < 4096) ? bytes_remaining : 4096;
        
        for (size_t i = 0; i < chunk_size; i++) {
            buffer[i] = get_enhanced_random_byte();
        }
        
        fwrite(buffer, 1, chunk_size, output);
        bytes_remaining -= chunk_size;
    }
    
    fclose(output);
    printf("Generated %zu bytes of enhanced random data in %s\n", num_bytes, filepath);
}

// Function to generate test files of different sizes
void generate_test_files() {
    const char* sizes[] = {"1KB", "10KB", "100KB", "1MB"};
    const size_t bytes[] = {1024, 10240, 102400, 1048576};
    
    for (int i = 0; i < 4; i++) {
        char filename[64];
        snprintf(filename, sizeof(filename), "random_%s.bin", sizes[i]);
        printf("Generating %s file: %s\n", sizes[i], filename);
        generate_random_file(filename, bytes[i]);
    }
}


// Function to test random number generation
void test_random_generator() {
    printf("\nGenerating test files for ENT analysis...\n");
    create_test_directory();
    
    // Generate both standard and enhanced random files
    printf("\nGenerating standard random files...\n");
    generate_test_files();
    
    printf("\nGenerating enhanced random files...\n");
    const char* sizes[] = {"1KB", "10KB", "100KB", "1MB"};
    const size_t bytes[] = {1024, 10240, 102400, 1048576};
    
    for (int i = 0; i < 4; i++) {
        char filename[64];
        snprintf(filename, sizeof(filename), "enhanced_random_%s.bin", sizes[i]);
        printf("Generating %s file: %s\n", sizes[i], filename);
        generate_enhanced_random_file(filename, bytes[i]);
    }
    
    // Print full paths for ENT commands
    char abs_path[PATH_MAX];
    if (realpath("random_test_files", abs_path) != NULL) {
        printf("\nTo test the files with ENT, run:\n");
        printf("ent %s/random_1KB.bin\n", abs_path);
        printf("ent -b %s/random_1KB.bin  # for bit-level analysis\n", abs_path);
        printf("ent -c %s/random_1KB.bin  # for character frequency analysis\n", abs_path);
        printf("ent %s/enhanced_random_1KB.bin  # for enhanced version\n", abs_path);
    }
}

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

// int main(void)
// {
//     #ifdef _WIN32
//         LARGE_INTEGER frequency;
//         QueryPerformanceFrequency(&frequency);
//     #endif
//     CLOCK_TYPE start, end;
//     sk_t sk = { 0 }; // private-key: (h0, h1)
//     pk_t pk = { 0 }; // public-key:  (g0, g1)
//     ct_t ct = { 0 }; // ciphertext:  (c0, c1)
//     ss_t k_enc = { 0 }; // shared secret after encapsulate
//     ss_t k_dec = { 0 }; // shared secret after decapsulate

//     const char* input1 = "The quick brown fox jumps over the lazy dog";
//     unsigned char output_openssl1[48ULL];
//     unsigned char output_new1[48ULL];
//     sha3_384_openssl(output_openssl1, (const unsigned char*)input1, strlen(input1));

//     //Compute hash using new function
//     sha3_384(output_new1, (const unsigned char*)input1, strlen(input1));
    
//     //Print the values of output_new1 and output_openssl1
//     printf("SHA vlastna implementacia vystup: ");
//     for (int i = 0; i < 48ULL; i++) {
//         printf("%02x", output_new1[i]);
//     }
//     printf("\n");

//     printf("SHA OpenSSL vystup: ");
//     for (int i = 0; i < 48ULL; i++) {
//         printf("%02x", output_openssl1[i]);
//     }
//     printf("\n");

//     if (memcmp(output_openssl1, output_new1, 48ULL) == 0) {
//         printf("Vysledky SHA3_384 hashovani su zhodne!\n");
//     } else {
//         printf("Vysledky SHA3_384 hashovani nie su zhodne!\n");
//     }
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
// AES256_ECB_AES(key, input, output_new);

// // Print first output (16 bytes)
// printf("AES OpenSSL vystup : ");
// for (int i = 0; i < 16; i++) {
//     printf("%02x", output_openssl[i]);
// }
// printf("\n");

// // Print second output (16 bytes)
// printf("AES vlastna implementancia vystup: ");
// for (int i = 0; i < 16; i++) {
//     printf("%02x", output_new[i]);
// }
// printf("\n");

// // Compare results (16 bytes)
// if (memcmp(output_openssl, output_new, 16) == 0) {
//     printf("Vysledky AES sifrovani su zhodne!\n");
// } else {
//     printf("Vysledky AES sifrovani nie su zhodne!\n");
// }

//     // //printf("\nStarting random number generation tests...\n");
//     // //test_random_generator();
//     // MSG("BIKE Demo Test:\n");

//     // FILE *fpt = fopen("valuesNove.csv", "w+");
//     // if (fpt == NULL) {
//     //     perror("Failed to open file");
//     //     return 1;
//     // }

//     // fprintf(fpt, "KeyGen Time (s),KeyGen Memory (KB),Encaps Time (s),Encaps Memory (KB),Decaps Time (s),Decaps Memory (KB)\n");

//     // for (uint32_t i = 1; i <= NUM_OF_CODE_TESTS; ++i) {
//     //     status_t res = SUCCESS;
//     //     MSG("r: %d Code test: %d \n", (int)R_BITS, i);

//     //     // Key generation
//     //     GET_TIME(start);
//     //     MEASURE("  keygen", res = static_cast<status_t>(crypto_kem_keypair(pk.raw, sk.raw)););
//     //     GET_TIME(end);
//     //     #ifdef _WIN32
//     //         double time_taken = GET_TIME_DIFF(end, start, frequency);
//     //     #else
//     //         double time_taken = GET_TIME_DIFF(end, start, 0);
//     //     #endif

//     //     fprintf(fpt, "%f,", time_taken);
//     //     print_memory_usage(fpt);

//     //     printf("Clients private key ");
//     //     for(size_t i = 0; i < 32; i++) {
//     //         printf("%02x", sk.raw[i]);
//     //     }
//     //     printf("\n");

//     //     if (res != SUCCESS) {
//     //         MSG("Keypair failed with error: %d\n", res);
//     //         continue;
//     //     }

//     //     for (uint32_t j = 1; j <= NUM_OF_ENCRYPTION_TESTS; ++j) {
//     //         uint32_t dec_rc = 0;

//     //         // Encapsulate
//     //         GET_TIME(start);
//     //         MEASURE("  encaps", res = static_cast<status_t>(crypto_kem_enc(ct.raw, k_enc.raw, pk.raw)););
//     //         GET_TIME(end);

            
//     //         #ifdef _WIN32
//     //             time_taken = GET_TIME_DIFF(end, start, frequency);
//     //         #else
//     //             time_taken = GET_TIME_DIFF(end, start, 0);
//     //         #endif

//     //         fprintf(fpt, "%f,", time_taken);
//     //         print_memory_usage(fpt);

//     //         if (res != SUCCESS) {
//     //             MSG("encapsulate failed with error: %d\n", res);
//     //             continue;
//     //         }

//     //         // Decapsulate
//     //         GET_TIME(start);
//     //         MEASURE("  decaps", dec_rc = crypto_kem_dec(k_dec.raw, ct.raw, sk.raw););
//     //         GET_TIME(end);

//     //         #ifdef _WIN32
//     //             time_taken = GET_TIME_DIFF(end, start, frequency);
//     //         #else
//     //             time_taken = GET_TIME_DIFF(end, start, 0);
//     //         #endif

//     //         fprintf(fpt, "%f,", time_taken);
//     //         print_memory_usage(fpt);
//     //         fprintf(fpt, "\n");

//     //         if (dec_rc != 0) {
//     //             MSG("Decoding failed after %d code tests and %d enc/dec tests!\n", i, j);
//     //         } else {
//     //             if (safe_cmp(k_enc.raw, k_dec.raw, sizeof(k_dec) / sizeof(uint64_t))) {
//     //                 MSG("Success! decapsulated key is the same as encapsulated key!\n");
//     //             } else {
//     //                 MSG("Failure! decapsulated key is NOT the same as encapsulated key!\n");
//     //             }
//     //         }
//     //     }
//     // }

//     // fclose(fpt);
//     return 0;
// }

// // Global variables to store memory usage data
// typedef struct {
//     const char* function_name;
//     long memory_before;
//     long memory_after;
//     long memory_used;
// } function_memory_data_t;

// #define MAX_FUNCTIONS 10
// function_memory_data_t function_memory[MAX_FUNCTIONS];
// int function_count = 0;

// Function to get current memory usage in KB
long get_current_memory_usage() {
    long rss = 0;
    FILE* file = fopen("/proc/self/status", "r");
    if (file) {
        char line[128];
        while (fgets(line, sizeof(line), file)) {
            if (strncmp(line, "VmRSS:", 6) == 0) {
                long kb;
                if (sscanf(line + 6, "%ld", &kb) == 1) {
                    rss = kb;
                    break;
                }
            }
        }
        fclose(file);
    }
    return rss;
}

// // Function to initialize memory measurement
// void init_memory_measurement() {
//     function_count = 0;
//     memset(function_memory, 0, sizeof(function_memory));
// }

// // Function to save memory measurement results to CSV
// void save_memory_measurements(const char* filename) {
//     FILE* file = fopen(filename, "w");
//     if (!file) {
//         printf("Error: Could not open file %s for writing\n", filename);
//         return;
//     }
    
//     fprintf(file, "Function,Memory Before (KB),Memory After (KB),Memory Used (KB)\n");
//     for (int i = 0; i < function_count; i++) {
//         fprintf(file, "%s,%ld,%ld,%ld\n", 
//                 function_memory[i].function_name,
//                 function_memory[i].memory_before,
//                 function_memory[i].memory_after,
//                 function_memory[i].memory_used);
//     }
    
//     fclose(file);
//     printf("Memory measurements saved to %s\n", filename);
// }

// // Function to measure memory usage of keypair generation
// int measure_keypair(uint8_t *pk, uint8_t *sk) {
//     if (function_count >= MAX_FUNCTIONS) {
//         printf("Warning: Maximum number of measured functions reached\n");
//         return crypto_kem_keypair(pk, sk);
//     }
    
//     function_memory_data_t* data = &function_memory[function_count++];
//     data->function_name = "crypto_kem_keypair";
    
//     // Force memory stabilization
//     usleep(10000);  // 10ms
    
//     // Measure memory before
//     data->memory_before = get_current_memory_usage();
    
//     // Run the function
//     int result = crypto_kem_keypair(pk, sk);
    
//     // Force memory stabilization
//     usleep(10000);  // 10ms
    
//     // Measure memory after
//     data->memory_after = get_current_memory_usage();
//     data->memory_used = data->memory_after - data->memory_before;
    
//     printf("Function: %s, Memory Used: %ld KB\n", 
//            data->function_name, data->memory_used);
    
//     return result;
// }

// // Function to measure memory usage of encapsulation
// int measure_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
//     if (function_count >= MAX_FUNCTIONS) {
//         printf("Warning: Maximum number of measured functions reached\n");
//         return crypto_kem_enc(ct, ss, pk);
//     }
    
//     function_memory_data_t* data = &function_memory[function_count++];
//     data->function_name = "crypto_kem_enc";
    
//     // Force memory stabilization
//     usleep(10000);  // 10ms
    
//     // Measure memory before
//     data->memory_before = get_current_memory_usage();
    
//     // Run the function
//     int result = crypto_kem_enc(ct, ss, pk);
    
//     // Force memory stabilization
//     usleep(10000);  // 10ms
    
//     // Measure memory after
//     data->memory_after = get_current_memory_usage();
//     data->memory_used = data->memory_after - data->memory_before;
    
//     printf("Function: %s, Memory Used: %ld KB\n", 
//            data->function_name, data->memory_used);
    
//     return result;
// }

// // Function to measure memory usage of decapsulation
// int measure_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
//     if (function_count >= MAX_FUNCTIONS) {
//         printf("Warning: Maximum number of measured functions reached\n");
//         return crypto_kem_dec(ss, ct, sk);
//     }
    
//     function_memory_data_t* data = &function_memory[function_count++];
//     data->function_name = "crypto_kem_dec";
    
//     // Force memory stabilization
//     usleep(10000);  // 10ms
    
//     // Measure memory before
//     data->memory_before = get_current_memory_usage();
    
//     // Run the function
//     int result = crypto_kem_dec(ss, ct, sk);
    
//     // Force memory stabilization
//     usleep(10000);  // 10ms
    
//     // Measure memory after
//     data->memory_after = get_current_memory_usage();
//     data->memory_used = data->memory_after - data->memory_before;
    
//     printf("Function: %s, Memory Used: %ld KB\n", 
//            data->function_name, data->memory_used);
    
//     return result;
// }
int save_binary_data(const char* filename, const uint8_t* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        printf("Error: Could not open file %s for writing\n", filename);
        return 0;
    }
    
    size_t written = fwrite(data, 1, size, file);
    fclose(file);
    
    if (written != size) {
        printf("Error: Could not write all data to file %s\n", filename);
        return 0;
    }
    
    return 1; // Success
}

// Function to load binary data from a file
int load_binary_data(const char* filename, uint8_t* data, size_t size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Could not open file %s for reading\n", filename);
        return 0;
    }
    
    size_t read = fread(data, 1, size, file);
    fclose(file);
    
    if (read != size) {
        printf("Error: Could not read all data from file %s\n", filename);
        return 0;
    }
    
    return 1; // Success
}

// Function to save public key
int save_public_key(const uint8_t* pk, size_t pk_size) {
    return save_binary_data("bike_public_key.bin", pk, pk_size);
}

// Function to save private key
int save_private_key(const uint8_t* sk, size_t sk_size) {
    return save_binary_data("bike_private_key.bin", sk, sk_size);
}

// Function to save ciphertext
int save_ciphertext(const uint8_t* ct, size_t ct_size) {
    return save_binary_data("bike_ciphertext.bin", ct, ct_size);
}

// Function to save shared secret
int save_shared_secret(const uint8_t* ss, size_t ss_size) {
    return save_binary_data("bike_shared_secret.bin", ss, ss_size);
}

// Function to load public key
int load_public_key(uint8_t* pk, size_t pk_size) {
    return load_binary_data("bike_public_key.bin", pk, pk_size);
}

// Function to load private key
int load_private_key(uint8_t* sk, size_t sk_size) {
    return load_binary_data("bike_private_key.bin", sk, sk_size);
}

// Function to load ciphertext
int load_ciphertext(uint8_t* ct, size_t ct_size) {
    return load_binary_data("bike_ciphertext.bin", ct, ct_size);
}

// Function to load shared secret
int load_shared_secret(uint8_t* ss, size_t ss_size) {
    return load_binary_data("bike_shared_secret.bin", ss, ss_size);
}

int main() {
    // Initialize data structures
    sk_t sk = { 0 };
    pk_t pk = { 0 };
    
    // Measure memory before
    long mem_before = get_current_memory_usage();
    
    // Measure time
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Generate key pair
    int result = crypto_kem_keypair(pk.raw, sk.raw);
    
    // Measure time end
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    // Measure memory after
    long mem_after = get_current_memory_usage();
    long mem_used = mem_after - mem_before;
    
    // Print results in CSV format to stdout (for script to capture)
    printf("%f,%ld,%ld,%ld\n", time_taken, mem_before, mem_after, mem_used);
    
    // Save keys for next step
    if (result == 0) {
        save_public_key(pk.raw, sizeof(pk_t));
        save_private_key(sk.raw, sizeof(sk_t));
    } else {
        fprintf(stderr, "Error generating keys: %d\n", result);
        return 1;
    }
    
    return 0;
}

// int main() {
//     // Initialize data structures
//     pk_t pk = { 0 };
//     ct_t ct = { 0 };
//     ss_t ss = { 0 };
    
//     // Load public key
//     if (!load_public_key(pk.raw, sizeof(pk_t))) {
//         fprintf(stderr, "Error loading public key\n");
//         return 1;
//     }
    
//     // Measure memory before
//     long mem_before = get_current_memory_usage();
    
//     // Measure time
//     struct timespec start, end;
//     clock_gettime(CLOCK_MONOTONIC, &start);
    
//     // Perform encapsulation
//     int result = crypto_kem_enc(ct.raw, ss.raw, pk.raw);
    
//     // Measure time end
//     clock_gettime(CLOCK_MONOTONIC, &end);
//     double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
//     // Measure memory after
//     long mem_after = get_current_memory_usage();
//     long mem_used = mem_after - mem_before;
    
//     // Print results in CSV format to stdout (for script to capture)
//     printf("%f,%ld,%ld,%ld\n", time_taken, mem_before, mem_after, mem_used);
    
//     // Save results for next step
//     if (result == 0) {
//         save_ciphertext(ct.raw, sizeof(ct_t));
//         save_shared_secret(ss.raw, sizeof(ss_t));
//     } else {
//         fprintf(stderr, "Error during encapsulation: %d\n", result);
//         return 1;
//     }
    
//     return 0;
// }
// int main() {
//     // Initialize data structures
//     sk_t sk = { 0 };
//     ct_t ct = { 0 };
//     ss_t ss = { 0 };
//     ss_t original_ss = { 0 };
    
//     // Load data from previous steps
//     if (!load_private_key(sk.raw, sizeof(sk_t))) {
//         fprintf(stderr, "Error loading private key\n");
//         return 1;
//     }
    
//     if (!load_ciphertext(ct.raw, sizeof(ct_t))) {
//         fprintf(stderr, "Error loading ciphertext\n");
//         return 1;
//     }
    
//     if (!load_shared_secret(original_ss.raw, sizeof(ss_t))) {
//         fprintf(stderr, "Error loading original shared secret\n");
//         return 1;
//     }
    
//     // Measure memory before
//     long mem_before = get_current_memory_usage();
    
//     // Measure time
//     struct timespec start, end;
//     clock_gettime(CLOCK_MONOTONIC, &start);
    
//     // Perform decapsulation
//     int result = crypto_kem_dec(ss.raw, ct.raw, sk.raw);
    
//     // Measure time end
//     clock_gettime(CLOCK_MONOTONIC, &end);
//     double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
//     // Measure memory after
//     long mem_after = get_current_memory_usage();
//     long mem_used = mem_after - mem_before;
    
//     // Verify correctness
//     int is_correct = 0;
//     if (result == 0) {
//         is_correct = (memcmp(ss.raw, original_ss.raw, sizeof(ss_t)) == 0) ? 1 : 0;
//     }
    
//     // Print results in CSV format to stdout (for script to capture)
//     printf("%f,%ld,%ld,%ld,%d\n", time_taken, mem_before, mem_after, mem_used, is_correct);
    
//     return 0;
// }