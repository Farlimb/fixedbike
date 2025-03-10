#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "kem.h"
#include "hash_wrapper.h"
#include "FromNIST/rng.h"
#include <time.h>
#include "FromNIST/aes.h"
#include <x86intrin.h>
#include <time.h>

// Cross-platform socket definitions
#ifdef _WIN32
#define SOCKET_TYPE SOCKET
#define INVALID_SOCK INVALID_SOCKET
#define SOCKET_ERROR_RETURN SOCKET_ERROR
#define CLOSE_SOCKET(s) closesocket(s)
#define GET_SOCKET_ERROR WSAGetLastError()
#else
#define SOCKET_TYPE int
#define INVALID_SOCK (-1)
#define SOCKET_ERROR_RETURN (-1)
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERROR errno
#endif

#define PORT 8080
#define BUFFER_SIZE 4096
#define BLOCK_SIZE 32
#define MAC_SIZE 48
#define MIN_PADDING 16
#define MAX_MESSAGE_SIZE 896
#define AES_KEYLEN 32
#define AES_BLOCKLEN 16

SOCKET_TYPE client_socket;
char buffer[BUFFER_SIZE];
typedef struct
{
    uint64_t raw_value;
    uint64_t microseconds;
    double temp;
} temp_data;

// Function to get high-precision time in microseconds
static inline uint64_t get_microseconds()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

// Function to get temperature reading
temp_data get_temp_reading()
{
    temp_data reading = {0};
    FILE *fp;
    char buffer[128];
    reading.microseconds = get_microseconds();
    fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (fp)
    {
        if (fgets(buffer, sizeof(buffer), fp) != NULL)
        {
            reading.raw_value = strtoull(buffer, NULL, 10);
            reading.temp = (double)reading.raw_value / 1000.0;
        }
        fclose(fp);
    }
    return reading;
}

// Enhanced random byte generation
unsigned char get_enhanced_random_byte()
{
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

typedef struct
{
    unsigned char iv[BLOCK_SIZE];
    unsigned char ciphertext[MAX_MESSAGE_SIZE + BLOCK_SIZE];
    unsigned char hmac[MAC_SIZE];
    size_t length;
} secure_message_t;

void generate_hmac(const unsigned char *key, size_t key_len,
                   const unsigned char *data, size_t data_len,
                   unsigned char *hmac)
{
    unsigned char k_ipad[BLOCK_SIZE];
    unsigned char k_opad[BLOCK_SIZE];

    memset(k_ipad, 0x36, BLOCK_SIZE);
    memset(k_opad, 0x5c, BLOCK_SIZE);

    for (size_t i = 0; i < key_len && i < BLOCK_SIZE; i++)
    {
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

bool encrypt_secure_message(const unsigned char *message, size_t message_len,
                            const ss_t *key, secure_message_t *secure_msg)
{
    if (message_len > MAX_MESSAGE_SIZE)
    {
        printf("Message too long: %zu bytes (max: %d)\n", message_len, MAX_MESSAGE_SIZE);
        return false;
    }

    randombytes(secure_msg->iv, AES_BLOCKLEN);

    size_t pad_len = AES_BLOCKLEN - (message_len % AES_BLOCKLEN);
    size_t total_len = message_len + pad_len;

    unsigned char *padded_msg = secure_msg->ciphertext;
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

void init_client(void)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup failed with error: %d\n", GET_SOCKET_ERROR);
        exit(EXIT_FAILURE);
    }
#endif

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCK)
    {
        printf("Socket creation failed with error: %d\n", GET_SOCKET_ERROR);
#ifdef _WIN32
        WSACleanup();
#endif
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    const char *server_ip = "127.0.0.1"; // Replace with your server's IP
    printf("Attempting to connect to %s:%d\n", server_ip, PORT);

#ifdef _WIN32
    serv_addr.sin_addr.s_addr = inet_addr(server_ip);
    if (serv_addr.sin_addr.s_addr == INADDR_NONE)
#else
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0)
#endif
    {
        printf("Invalid IP address\n");
        CLOSE_SOCKET(client_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        exit(EXIT_FAILURE);
    }

// Set timeout
#ifdef _WIN32
    DWORD timeout = 10000; // 10 seconds
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif

    printf("Attempting connection...\n");
    if (connect(client_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR_RETURN)
    {
        printf("Connect failed with error: %d\n", GET_SOCKET_ERROR);
        CLOSE_SOCKET(client_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        exit(EXIT_FAILURE);
    }

    printf("Connected to server successfully\n");
}

void send_message(const void *data, size_t size)
{
    size_t total_sent = 0;
    const char *data_ptr = (const char *)data;

    while (total_sent < size)
    {
#ifdef _WIN32
        int sent = send(client_socket, data_ptr + total_sent,
                        (int)(size - total_sent), 0);
#else
        ssize_t sent = send(client_socket, data_ptr + total_sent,
                            size - total_sent, 0);
#endif

        if (sent == SOCKET_ERROR_RETURN)
        {
            printf("Send failed with error: %d\n", GET_SOCKET_ERROR);
            CLOSE_SOCKET(client_socket);
#ifdef _WIN32
            WSACleanup();
#endif
            exit(EXIT_FAILURE);
        }
        total_sent += sent;
    }
}

void receive_message(void *data, size_t size)
{
    size_t total_received = 0;
    char *data_ptr = (char *)data;

    while (total_received < size)
    {
#ifdef _WIN32
        int received = recv(client_socket, data_ptr + total_received,
                            (int)(size - total_received), 0);
#else
        ssize_t received = recv(client_socket, data_ptr + total_received,
                                size - total_received, 0);
#endif

        if (received <= 0)
        {
            printf("Receive failed with error: %d\n", GET_SOCKET_ERROR);
            CLOSE_SOCKET(client_socket);
#ifdef _WIN32
            WSACleanup();
#endif
            exit(EXIT_FAILURE);
        }
        total_received += received;
    }
}

void combine_secrets(const ss_t *secret1, const ss_t *secret2, ss_t *final_secret)
{
    int compare = memcmp(secret1->raw, secret2->raw, sizeof(ss_t));
    unsigned char combined[sizeof(ss_t) * 2];

    if (compare < 0)
    {
        memcpy(combined, secret1->raw, sizeof(ss_t));
        memcpy(combined + sizeof(ss_t), secret2->raw, sizeof(ss_t));
    }
    else
    {
        memcpy(combined, secret2->raw, sizeof(ss_t));
        memcpy(combined + sizeof(ss_t), secret1->raw, sizeof(ss_t));
    }

    sha3_384(final_secret->raw, combined, sizeof(combined));
}

int main(void)
{
    // sk_t client_sk = { 0 };
    // pk_t client_pk = { 0 };
    sk_t client_sk;
    memset(&client_sk, 0, sizeof(sk_t));
    pk_t client_pk;
    memset(&client_pk, 0, sizeof(pk_t));
    pk_t server_pk = {0};
    ct_t client_ct = {0};
    ct_t server_ct = {0};
    ss_t client_shared_secret1 = {0};
    ss_t client_shared_secret2 = {0};

    init_client();
    MSG("BIKE Client Started:\n");

    // Initialize random seed with different value for client
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++)
    {
        entropy_input[i] = get_enhanced_random_byte();
    }
    printf("Entropy input: ");
    for (size_t i = 0; i < 48; i++)
    {
        printf("%02x", entropy_input[i]);
    }
    randombytes_init(entropy_input, NULL, 256);

    // Generate client's keypair
    status_t res = static_cast<status_t>(crypto_kem_keypair(client_pk.raw, client_sk.raw));
    if (res != SUCCESS)
    {
        MSG("Client keypair generation failed\n");
        return -1;
    }

    printf("Clients private key ");
    for (size_t i = 0; i < 1024; i++)
    {
        printf("%02x", client_sk.raw[i]);
    }
    printf("...\n");
    printf("Client public key: ");
    for (size_t i = 0; i < 32; i++)
    { // Print first 32 bytes for brevity
        printf("%02x", client_pk.raw[i]);
    }
    printf("...\n");

    // Exchange public keys
    receive_message(server_pk.raw, sizeof(server_pk.raw));
    send_message(client_pk.raw, sizeof(client_pk.raw));

    printf("Received server public key: ");
    for (size_t i = 0; i < 32; i++)
    {
        printf("%02x", server_pk.raw[i]);
    }
    printf("...\n");

    // Generate client's ciphertext and first shared secret
    res = static_cast<status_t>(crypto_kem_enc(client_ct.raw, client_shared_secret1.raw, server_pk.raw));
    if (res != SUCCESS)
    {
        MSG("Encapsulation failed\n");
        return -1;
    }

    printf("Client shared secret 1: ");
    for (size_t i = 0; i < sizeof(ss_t); i++)
    {
        printf("%02x", client_shared_secret1.raw[i]);
    }
    printf("\n");

    // Exchange ciphertexts
    send_message(client_ct.raw, sizeof(client_ct.raw));
    receive_message(server_ct.raw, sizeof(server_ct.raw));

    // Decapsulate server's ciphertext
    res = static_cast<status_t>(crypto_kem_dec(client_shared_secret2.raw, server_ct.raw, client_sk.raw));
    if (res != SUCCESS)
    {
        MSG("Decapsulation failed\n");
        return -1;
    }

    printf("Client shared secret 2: ");
    for (size_t i = 0; i < sizeof(ss_t); i++)
    {
        printf("%02x", client_shared_secret2.raw[i]);
    }
    printf("\n");

    // Combine shared secrets using a more robust method
    ss_t final_shared_secret = {0};
    combine_secrets(&client_shared_secret1, &client_shared_secret2, &final_shared_secret);

    printf("Final shared secret: ");
    for (size_t i = 0; i < sizeof(ss_t); i++)
    {
        printf("%02x", final_shared_secret.raw[i]);
    }
    printf("\n");
    while (1)
    {
        printf("Enter message (or 'quit' to exit): ");
        char message[MAX_MESSAGE_SIZE];
        if (fgets(message, sizeof(message), stdin) == NULL)
        {
            break;
        }

        message[strcspn(message, "\n")] = 0;
        if (strcmp(message, "quit") == 0)
            break;

        size_t message_len = strlen(message);
        if (message_len > MAX_MESSAGE_SIZE)
        {
            printf("Message too long (max %d bytes)\n", MAX_MESSAGE_SIZE);
            continue;
        }

        secure_message_t secure_msg = {0}; // Initialize to zero
        if (!encrypt_secure_message((unsigned char *)message, message_len,
                                    &final_shared_secret, &secure_msg))
        {
            printf("Encryption failed\n");
            continue;
        }
        printf("Secure message ciphertext: ");
        for (size_t i = 0; i < sizeof(secure_msg.ciphertext); i++)
        {
            printf("%02x", secure_msg.ciphertext[i]);
        }
        printf("\n");
        send_message(&secure_msg, sizeof(secure_message_t));
    }
    CLOSE_SOCKET(client_socket);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}