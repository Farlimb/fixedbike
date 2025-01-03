#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include "kem.h"
#include "utilities.h"
#include "measurements.h"
#include "hash_wrapper.h"
#include "FromNIST/rng.h"
#include <time.h>
#define PORT 8080
#define BUFFER_SIZE 4096

int client_socket;
char buffer[BUFFER_SIZE];

void init_client(void) {
    struct sockaddr_in serv_addr;

    // Create socket
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(client_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");
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
    sk_t client_sk = { 0 };
    pk_t client_pk = { 0 };
    
    pk_t server_pk = { 0 };
    ct_t client_ct = { 0 };
    ct_t server_ct = { 0 };
    ss_t client_shared_secret1 = { 0 };
    ss_t client_shared_secret2 = { 0 };

    init_client();
    MSG("BIKE Client Started:\n");

    // Initialize random seed with different value for client
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) {
        entropy_input[i] = (time(NULL) + i) & 0xFF;  // Client uses time + position
    }
    // Add a client-specific modifier
    entropy_input[0] ^= 0xAA;  // XOR with a different value for client
    randombytes_init(entropy_input, NULL, 256);

    // Generate client's keypair
    status_t res = static_cast<status_t>(crypto_kem_keypair(client_pk.raw, client_sk.raw));
    if (res != SUCCESS) {
        MSG("Client keypair generation failed\n");
        return -1;
    }
    
    printf("Client public key: ");
    for(size_t i = 0; i < 32; i++) {  // Print first 32 bytes for brevity
        printf("%02x", client_pk.raw[i]);
    }
    printf("...\n");

    // Exchange public keys
    receive_message(server_pk.raw, sizeof(server_pk.raw));
    send_message(client_pk.raw, sizeof(client_pk.raw));
    
    printf("Received server public key: ");
    for(size_t i = 0; i < 32; i++) {
        printf("%02x", server_pk.raw[i]);
    }
    printf("...\n");

    // Generate client's ciphertext and first shared secret
    res = static_cast<status_t>(crypto_kem_enc(client_ct.raw, client_shared_secret1.raw, server_pk.raw));
    if (res != SUCCESS) {
        MSG("Encapsulation failed\n");
        return -1;
    }
    
    printf("Client shared secret 1: ");
    for(size_t i = 0; i < sizeof(ss_t); i++) {
        printf("%02x", client_shared_secret1.raw[i]);
    }
    printf("\n");

    // Exchange ciphertexts
    send_message(client_ct.raw, sizeof(client_ct.raw));
    receive_message(server_ct.raw, sizeof(server_ct.raw));

    // Decapsulate server's ciphertext
    res = static_cast<status_t>(crypto_kem_dec(client_shared_secret2.raw, server_ct.raw, client_sk.raw));
    if (res != SUCCESS) {
        MSG("Decapsulation failed\n");
        return -1;
    }

    printf("Client shared secret 2: ");
    for(size_t i = 0; i < sizeof(ss_t); i++) {
        printf("%02x", client_shared_secret2.raw[i]);
    }
    printf("\n");

    // Combine shared secrets using a more robust method
    ss_t final_shared_secret = { 0 };
    combine_secrets(&client_shared_secret1, &client_shared_secret2, &final_shared_secret);

    printf("Final shared secret: ");
    for(size_t i = 0; i < sizeof(ss_t); i++) {
        printf("%02x", final_shared_secret.raw[i]);
    }
    printf("\n");
    while(1) {
        printf("Enter message (or 'quit' to exit): ");
        char message[1024];
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = 0;
        
        if(strcmp(message, "quit") == 0) {
            break;
        }
        
        size_t msg_len = strlen(message);
        unsigned char encrypted[1024 + 48];
        unsigned char iv[16];
        
        // Generate IV
        generate_iv(iv, 16);
        
        // Create extended message and encrypt
        unsigned char extended[1024 + 48];
        create_extended_message((unsigned char*)message, msg_len, extended);
        
        // Encrypt the extended message
        encrypt_message((unsigned char*)message, msg_len, encrypted, iv, &final_shared_secret);
        
        print_hex("Encrypted data", encrypted, msg_len + 48);
        
        // Send data
        send_message(iv, 16);
        send_message(&msg_len, sizeof(msg_len));
        send_message(encrypted, msg_len + 48);
    }
    close(client_socket);
    return 0;
}