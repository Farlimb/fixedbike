#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include "kem.h"
#include "hash_wrapper.h"
#include "FromNIST/rng.h"
#include <time.h>
#include "FromNIST/aes.h"

#define PORT 8080
#define BUFFER_SIZE 4096
#define BLOCK_SIZE 32
#define MAC_SIZE 48
#define MIN_PADDING 16
#define MAX_MESSAGE_SIZE 896
#define AES_KEYLEN 32
#define AES_BLOCKLEN 16

int client_socket;
char buffer[BUFFER_SIZE];

typedef struct {
    unsigned char iv[BLOCK_SIZE];
    unsigned char ciphertext[MAX_MESSAGE_SIZE + BLOCK_SIZE];
    unsigned char hmac[MAC_SIZE];
    size_t length;
} secure_message_t;

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

bool encrypt_secure_message(const unsigned char* message, size_t message_len,
                          const ss_t* key, secure_message_t* secure_msg) {
    if (message_len > MAX_MESSAGE_SIZE) {
        printf("Message too long: %zu bytes (max: %d)\n", message_len, MAX_MESSAGE_SIZE);
        return false;
    }

    randombytes(secure_msg->iv, AES_BLOCKLEN);

    size_t pad_len = AES_BLOCKLEN - (message_len % AES_BLOCKLEN);
    size_t total_len = message_len + pad_len;

    unsigned char* padded_msg = secure_msg->ciphertext;
    memcpy(padded_msg, message, message_len);
    memset(padded_msg + message_len, pad_len, pad_len);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key->raw, secure_msg->iv);

    AES_CBC_encrypt_buffer(&ctx, padded_msg, total_len);
    secure_msg->length = total_len;

    unsigned char hmac_data[AES_BLOCKLEN + MAX_MESSAGE_SIZE + AES_BLOCKLEN];
    memcpy(hmac_data, secure_msg->iv, AES_BLOCKLEN);
    memcpy(hmac_data + AES_BLOCKLEN, secure_msg->ciphertext, total_len);
    generate_hmac(key->raw, sizeof(ss_t), hmac_data, AES_BLOCKLEN + total_len,
                 secure_msg->hmac);

    return true;
}

void init_client(void) {
    struct sockaddr_in serv_addr;

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "172.27.240.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

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
    // sk_t client_sk = { 0 };
    // pk_t client_pk = { 0 };
    sk_t client_sk;
        memset(&client_sk, 0, sizeof(sk_t));
        pk_t client_pk;
        memset(&client_pk, 0, sizeof(pk_t));
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
        entropy_input[i] = rand() ^ ((unsigned char)time(NULL) + i);
    }
    randombytes_init(entropy_input, NULL, 256);

    // Generate client's keypair
    status_t res = static_cast<status_t>(crypto_kem_keypair(client_pk.raw, client_sk.raw));
    if (res != SUCCESS) {
        MSG("Client keypair generation failed\n");
        return -1;
    }
    
    printf("Clients private key ");
        for(size_t i = 0; i < 1024; i++) {
            printf("%02x", client_sk.raw[i]);
        }
    printf("...\n");
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
        char message[MAX_MESSAGE_SIZE];
        if (fgets(message, sizeof(message), stdin) == NULL) {
            break;
        }
        
        message[strcspn(message, "\n")] = 0;
        if (strcmp(message, "quit") == 0) break;

        size_t message_len = strlen(message);
        if (message_len > MAX_MESSAGE_SIZE) {
            printf("Message too long (max %d bytes)\n", MAX_MESSAGE_SIZE);
            continue;
        }

        secure_message_t secure_msg = {0};  // Initialize to zero
        if (!encrypt_secure_message((unsigned char*)message, message_len,
                                &final_shared_secret, &secure_msg)) {
            printf("Encryption failed\n");
            continue;
        }
        printf("Secure message ciphertext: ");
        for(size_t i = 0; i < sizeof(secure_msg.ciphertext); i++) {
            printf("%02x", secure_msg.ciphertext[i]);
        }
        printf("\n");
        send_message(&secure_msg, sizeof(secure_message_t));
    }
    close(client_socket);
    return 0;
}