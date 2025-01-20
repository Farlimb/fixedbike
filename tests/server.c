#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include "kem.h"
#include "hash_wrapper.h"
#include "FromNIST/rng.h"
#include "FromNIST/aes.h"

#define PORT 8080
#define BUFFER_SIZE 4096
#define BLOCK_SIZE 32
#define MAC_SIZE 48
#define MIN_PADDING 16
#define MAX_MESSAGE_SIZE 896
#define AES_KEYLEN 32
#define AES_BLOCKLEN 16

typedef struct {
    unsigned char iv[BLOCK_SIZE];
    unsigned char ciphertext[MAX_MESSAGE_SIZE + BLOCK_SIZE];
    unsigned char hmac[MAC_SIZE];
    size_t length;
} secure_message_t;

int server_fd, client_socket;
char buffer[BUFFER_SIZE];

void generate_hmac(const unsigned char* key, size_t key_len,
                  const unsigned char* data, size_t data_len,
                  unsigned char* hmac) {
    unsigned char k_ipad[BLOCK_SIZE];
    unsigned char k_opad[BLOCK_SIZE];
    
    memset(k_ipad, 0x36, BLOCK_SIZE);
    memset(k_opad, 0x5c, BLOCK_SIZE);
    
    for (size_t i = 0; i < key_len && i < BLOCK_SIZE; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    
    unsigned char inner_hash[MAC_SIZE];
    unsigned char temp[BLOCK_SIZE + 1024];
    
    memcpy(temp, k_ipad, BLOCK_SIZE);
    memcpy(temp + BLOCK_SIZE, data, data_len);
    sha3_384(inner_hash, temp, BLOCK_SIZE + data_len);
    
    memcpy(temp, k_opad, BLOCK_SIZE);
    memcpy(temp + BLOCK_SIZE, inner_hash, MAC_SIZE);
    sha3_384(hmac, temp, BLOCK_SIZE + MAC_SIZE);
}

bool decrypt_secure_message(const secure_message_t* secure_msg,
                          const ss_t* key,
                          unsigned char* decrypted,
                          size_t* decrypted_len) {
    if (secure_msg->length > MAX_MESSAGE_SIZE + AES_BLOCKLEN || 
        secure_msg->length % AES_BLOCKLEN != 0) {
        return false;
    }

    unsigned char hmac_data[AES_BLOCKLEN + MAX_MESSAGE_SIZE + AES_BLOCKLEN];
    memcpy(hmac_data, secure_msg->iv, AES_BLOCKLEN);
    memcpy(hmac_data + AES_BLOCKLEN, secure_msg->ciphertext, secure_msg->length);
    
    unsigned char calculated_hmac[MAC_SIZE];
    generate_hmac(key->raw, sizeof(ss_t), hmac_data, AES_BLOCKLEN + secure_msg->length,
                 calculated_hmac);

    if (memcmp(calculated_hmac, secure_msg->hmac, MAC_SIZE) != 0) {
        return false;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key->raw, secure_msg->iv);
    
    unsigned char temp_buf[MAX_MESSAGE_SIZE + AES_BLOCKLEN];
    memcpy(temp_buf, secure_msg->ciphertext, secure_msg->length);
    AES_CBC_decrypt_buffer(&ctx, temp_buf, secure_msg->length);

    unsigned char pad_len = temp_buf[secure_msg->length - 1];
    if (pad_len > AES_BLOCKLEN || pad_len == 0) {
        return false;
    }

    for (size_t i = secure_msg->length - pad_len; i < secure_msg->length; i++) {
        if (temp_buf[i] != pad_len) {
            return false;
        }
    }

    *decrypted_len = secure_msg->length - pad_len;
    memcpy(decrypted, temp_buf, *decrypted_len);
    
    return true;
}

void init_server(void) {
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    if ((client_socket = accept(server_fd, (struct sockaddr*)&address, 
                            (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }
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
    int compare = memcmp(secret1->raw, secret2->raw, sizeof(ss_t));
    unsigned char combined[sizeof(ss_t) * 2];
    
    if (compare < 0) {
        memcpy(combined, secret1->raw, sizeof(ss_t));
        memcpy(combined + sizeof(ss_t), secret2->raw, sizeof(ss_t));
    } else {
        memcpy(combined, secret2->raw, sizeof(ss_t));
        memcpy(combined + sizeof(ss_t), secret1->raw, sizeof(ss_t));
    }
    
    sha3_384(final_secret->raw, combined, sizeof(combined));
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
        printf("Servers private key ");
        for(size_t i = 0; i < 1024; i++) {
            printf("%02x", server_sk.raw[i]);
        }
        printf("...\n");

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
            secure_message_t secure_msg = {0};  // Initialize to zero
            unsigned char decrypted[MAX_MESSAGE_SIZE + BLOCK_SIZE] = {0};
            size_t decrypted_len;

            receive_message(&secure_msg, sizeof(secure_message_t));

            if (decrypt_secure_message(&secure_msg, &final_shared_secret,
                                    decrypted, &decrypted_len)) {
                decrypted[decrypted_len] = '\0';
                printf("Verified message: %s\n", decrypted);
            } else {
                printf("Message verification failed!\n");
            }
        }
        close(client_socket);
        close(server_fd);
        return 0;
    }