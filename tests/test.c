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

    //printf("\nStarting random number generation tests...\n");
    test_random_generator();
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


//AFTER THIS ARE MEASUREMENTS OF TIME AND MEMORY
//AFTER THIS ARE MEASUREMENTS OF TIME AND MEMORY
//AFTER THIS ARE MEASUREMENTS OF TIME AND MEMORY
//AFTER THIS ARE MEASUREMENTS OF TIME AND MEMORY
//AFTER THIS ARE MEASUREMENTS OF TIME AND MEMORY
//AFTER THIS ARE MEASUREMENTS OF TIME AND MEMORY


// Function to get current memory usage in KB
// long get_current_memory_usage() {
//     long rss = 0;
//     FILE* file = fopen("/proc/self/status", "r");
//     if (file) {
//         char line[128];
//         while (fgets(line, sizeof(line), file)) {
//             if (strncmp(line, "VmRSS:", 6) == 0) {
//                 long kb;
//                 if (sscanf(line + 6, "%ld", &kb) == 1) {
//                     rss = kb;
//                     break;
//                 }
//             }
//         }
//         fclose(file);
//     }
//     return rss;
// }

// int save_binary_data(const char* filename, const uint8_t* data, size_t size) {
//     FILE* file = fopen(filename, "wb");
//     if (!file) {
//         printf("Error: Could not open file %s for writing\n", filename);
//         return 0;
//     }
    
//     size_t written = fwrite(data, 1, size, file);
//     fclose(file);
    
//     if (written != size) {
//         printf("Error: Could not write all data to file %s\n", filename);
//         return 0;
//     }
    
//     return 1; // Success
// }

// // Function to load binary data from a file
// int load_binary_data(const char* filename, uint8_t* data, size_t size) {
//     FILE* file = fopen(filename, "rb");
//     if (!file) {
//         printf("Error: Could not open file %s for reading\n", filename);
//         return 0;
//     }
    
//     size_t read = fread(data, 1, size, file);
//     fclose(file);
    
//     if (read != size) {
//         printf("Error: Could not read all data from file %s\n", filename);
//         return 0;
//     }
    
//     return 1; // Success
// }

// // Function to save public key
// int save_public_key(const uint8_t* pk, size_t pk_size) {
//     return save_binary_data("bike_public_key.bin", pk, pk_size);
// }

// // Function to save private key
// int save_private_key(const uint8_t* sk, size_t sk_size) {
//     return save_binary_data("bike_private_key.bin", sk, sk_size);
// }

// // Function to save ciphertext
// int save_ciphertext(const uint8_t* ct, size_t ct_size) {
//     return save_binary_data("bike_ciphertext.bin", ct, ct_size);
// }

// // Function to save shared secret
// int save_shared_secret(const uint8_t* ss, size_t ss_size) {
//     return save_binary_data("bike_shared_secret.bin", ss, ss_size);
// }

// // Function to load public key
// int load_public_key(uint8_t* pk, size_t pk_size) {
//     return load_binary_data("bike_public_key.bin", pk, pk_size);
// }

// // Function to load private key
// int load_private_key(uint8_t* sk, size_t sk_size) {
//     return load_binary_data("bike_private_key.bin", sk, sk_size);
// }

// // Function to load ciphertext
// int load_ciphertext(uint8_t* ct, size_t ct_size) {
//     return load_binary_data("bike_ciphertext.bin", ct, ct_size);
// }

// // Function to load shared secret
// int load_shared_secret(uint8_t* ss, size_t ss_size) {
//     return load_binary_data("bike_shared_secret.bin", ss, ss_size);
// }

//KEYGEN
// int main() {
//     // Initialize data structures
//     sk_t sk = { 0 };
//     pk_t pk = { 0 };
    
//     // Measure memory before
//     long mem_before = get_current_memory_usage();
    
//     // Measure time
//     struct timespec start, end;
//     clock_gettime(CLOCK_MONOTONIC, &start);
    
//     // Generate key pair
//     int result = crypto_kem_keypair(pk.raw, sk.raw);
    
//     // Measure time end
//     clock_gettime(CLOCK_MONOTONIC, &end);
//     double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
//     // Measure memory after
//     long mem_after = get_current_memory_usage();
//     long mem_used = mem_after - mem_before;
    
//     // Print results in CSV format to stdout (for script to capture)
//     printf("%f,%ld,%ld,%ld\n", time_taken, mem_before, mem_after, mem_used);
    
//     // Save keys for next step
//     if (result == 0) {
//         save_public_key(pk.raw, sizeof(pk_t));
//         save_private_key(sk.raw, sizeof(sk_t));
//     } else {
//         fprintf(stderr, "Error generating keys: %d\n", result);
//         return 1;
//     }
    
//     return 0;
// }

//ENCAPS
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

//DECAPS
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