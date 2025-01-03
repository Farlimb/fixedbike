    #include <time.h>
    #include <stdbool.h>
    #include <sys/resource.h>
    #include <stdio.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #include <string.h>
    #include <stdlib.h>
    #include "kem.h"
    #include "utilities.h"
    #include "measurements.h"
    #include "hash_wrapper.h"
    #include "FromNIST/rng.h"

    #define PORT 8080
    #define BUFFER_SIZE 4096

    int server_fd, client_socket;
    char buffer[BUFFER_SIZE];

    void init_server(void) {
        struct sockaddr_in address;
        int opt = 1;
        int addrlen = sizeof(address);
        
        // Create socket
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation failed");
            exit(EXIT_FAILURE);
        }
        
        // Set socket options
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            perror("Setsockopt failed");
            exit(EXIT_FAILURE);
        }
        
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);
        
        // Bind socket
        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            perror("Bind failed");
            exit(EXIT_FAILURE);
        }
        
        // Listen for connections
        if (listen(server_fd, 3) < 0) {
            perror("Listen failed");
            exit(EXIT_FAILURE);
        }
        
        // Accept connection
        if ((client_socket = accept(server_fd, (struct sockaddr*)&address, 
                                (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }
        
        printf("Client connected\n");
    }

    void send_message(const void* data, size_t size) {
        size_t total_sent = 0;
        const char* data_ptr = (const char*)data;
        
        while (total_sent < size) {
            ssize_t sent = send(client_socket, data_ptr + total_sent, size - total_sent, 0);
            if (sent < 0) {
                perror("Send failed");
                exit(EXIT_FAILURE);
            }
            total_sent += sent;
        }
    }

    void receive_message(void* data, size_t size) {
        size_t total_received = 0;
        char* data_ptr = (char*)data;
        
        while (total_received < size) {
            ssize_t received = read(client_socket, data_ptr + total_received, size - total_received);
            if (received <= 0) {
                perror("Receive failed");
                exit(EXIT_FAILURE);
            }
            total_received += received;
        }
    }

    void combine_secrets(const ss_t* secret1, const ss_t* secret2, ss_t* final_secret) {
        // Compare the secrets to determine order
        int compare = memcmp(secret1->raw, secret2->raw, sizeof(ss_t));
        
        // Combine the secrets in consistent order (smaller first)
        unsigned char combined[sizeof(ss_t) * 2];
        if (compare < 0) {
            memcpy(combined, secret1->raw, sizeof(ss_t));
            memcpy(combined + sizeof(ss_t), secret2->raw, sizeof(ss_t));
        } else {
            memcpy(combined, secret2->raw, sizeof(ss_t));
            memcpy(combined + sizeof(ss_t), secret1->raw, sizeof(ss_t));
        }
        
        // Hash the combined secrets using SHA3-384
        sha3_384(final_secret->raw, combined, sizeof(combined));
    }

    void generate_iv(unsigned char* iv, size_t iv_len) {
    // Use the existing randombytes function from NIST RNG
    randombytes(iv, iv_len);
}

// Function to print hex data for debugging
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for(size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Modified create_extended_message function with verification
void create_extended_message(const unsigned char* message, size_t message_len, 
                           unsigned char* extended) {
    // Create hash of the original message
    unsigned char hash[48];
    sha3_384(hash, message, message_len);
    
    // Print original message and its hash for debugging
    print_hex("Original message", message, message_len);
    print_hex("Generated hash", hash, 48);
    
    // Combine message and hash
    memcpy(extended, message, message_len);
    memcpy(extended + message_len, hash, 48);
}

void encrypt_message(const unsigned char* message, size_t message_len, 
                    unsigned char* encrypted, const unsigned char* iv, 
                    const ss_t* key) {
    // Create extended message (message + 48-byte hash)
    unsigned char extended[1024 + 48];
    create_extended_message(message, message_len, extended);
    size_t total_len = message_len + 48;  // Always add 48 bytes for hash
    
    // Encrypt the extended message
    for(size_t i = 0; i < total_len; i++) {
        encrypted[i] = extended[i] ^ iv[i % 16];
    }
    for(size_t i = 0; i < total_len; i++) {
        encrypted[i] = encrypted[i] ^ key->raw[i % sizeof(ss_t)];
    }
}

// Modified decrypt_message function with verification
bool decrypt_message(const unsigned char* encrypted, size_t msg_len,
                    const unsigned char* iv, unsigned char* decrypted,
                    const ss_t* key) {
    size_t total_len = msg_len + 48;
    
    // Decrypt the entire message
    for(size_t i = 0; i < total_len; i++) {
        decrypted[i] = encrypted[i] ^ key->raw[i % sizeof(ss_t)];
    }
    for(size_t i = 0; i < total_len; i++) {
        decrypted[i] = decrypted[i] ^ iv[i % 16];
    }
    
    // Verify hash
    unsigned char* received_hash = decrypted + msg_len;
    unsigned char calculated_hash[48];
    sha3_384(calculated_hash, decrypted, msg_len);
    
    print_hex("Received hash", received_hash, 48);
    print_hex("Calculated hash", calculated_hash, 48);
    
    return (memcmp(received_hash, calculated_hash, 48) == 0);
}

    int main(void) {
        sk_t server_sk = { 0 };
        pk_t server_pk = { 0 };
        
        pk_t client_pk = { 0 };
        ct_t server_ct = { 0 };
        ct_t client_ct = { 0 };
        ss_t server_shared_secret1 = { 0 };
        ss_t server_shared_secret2 = { 0 };

        init_server();
        MSG("BIKE Server Started:\n");

        // Initialize random seed with different value for server
         unsigned char entropy_input[48];
        for (int i = 0; i < 48; i++) {
            entropy_input[i] = (time(NULL) + i + 100) & 0xFF;  // Server uses time + position + 100
        }
        // Add a server-specific modifier
        entropy_input[0] ^= 0x55;  // XOR with a different value for server
        randombytes_init(entropy_input, NULL, 256);

        // Generate server's keypair
        status_t res = static_cast<status_t>(crypto_kem_keypair(server_pk.raw, server_sk.raw));
        if (res != SUCCESS) {
            MSG("Server keypair generation failed\n");
            return -1;
        }   

        printf("Server public key: ");
        for(size_t i = 0; i < 32; i++) {
            printf("%02x", server_pk.raw[i]);
        }
        printf("...\n");

        // Exchange public keys
        send_message(server_pk.raw, sizeof(server_pk.raw));
        receive_message(client_pk.raw, sizeof(client_pk.raw));

        printf("Received client public key: ");
        for(size_t i = 0; i < 32; i++) {
            printf("%02x", client_pk.raw[i]);
        }
        printf("...\n");

        // Generate server's ciphertext and first shared secret
        res = static_cast<status_t>(crypto_kem_enc(server_ct.raw, server_shared_secret1.raw, client_pk.raw));
        if (res != SUCCESS) {
            MSG("Encapsulation failed\n");
            return -1;
        }

        printf("Server shared secret 1: ");
        for(size_t i = 0; i < sizeof(ss_t); i++) {
            printf("%02x", server_shared_secret1.raw[i]);
        }
        printf("\n");

        // Exchange ciphertexts
        receive_message(client_ct.raw, sizeof(client_ct.raw));
        send_message(server_ct.raw, sizeof(server_ct.raw));

        // Decapsulate client's ciphertext
        res = static_cast<status_t>(crypto_kem_dec(server_shared_secret2.raw, client_ct.raw, server_sk.raw));
        if (res != SUCCESS) {
            MSG("Decapsulation failed\n");
            return -1;
        }

        printf("Server shared secret 2: ");
        for(size_t i = 0; i < sizeof(ss_t); i++) {
            printf("%02x", server_shared_secret2.raw[i]);
        }
        printf("\n");

        // Combine shared secrets
        ss_t final_shared_secret = { 0 };
        combine_secrets(&server_shared_secret1, &server_shared_secret2, &final_shared_secret);

        printf("Final shared secret: ");
        for(size_t i = 0; i < sizeof(ss_t); i++) {
            printf("%02x", final_shared_secret.raw[i]);
        }
        printf("\n");
        while(1) {
            unsigned char iv[16];
            size_t msg_len;
            unsigned char encrypted[1024 + 48];
            unsigned char decrypted[1024 + 48];
            
            // Receive data
            receive_message(iv, 16);
            receive_message(&msg_len, sizeof(msg_len));
            receive_message(encrypted, msg_len + 48);
            
            print_hex("Received encrypted data", encrypted, msg_len + 48);
            
            // Decrypt and verify
            if (decrypt_message(encrypted, msg_len, iv, decrypted, &final_shared_secret)) {
                printf("Message verified successfully!\n");
                decrypted[msg_len] = '\0';
                printf("Decrypted message: %s\n", decrypted);
            } else {
                printf("WARNING: Message verification failed!\n");
                decrypted[msg_len] = '\0';
                printf("Decrypted message (unverified): %s\n", decrypted);
            }
            printf("\n");
        }
        close(client_socket);
        close(server_fd);
        return 0;
    }