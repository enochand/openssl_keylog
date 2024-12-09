#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>

// Callback function to log session keys
void ssl_keylog_callback(const SSL *ssl, const char *line) {
    FILE *fp = fopen("session_keys.log", "a");
    if (fp != NULL) {
        fprintf(fp, "%s\n", line);
        fclose(fp);
    }
}

// Function to initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to create SSL context
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to create and connect socket
int create_socket(char *hostname, char *port) {
    int sock;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror("Unable to get host address");
        exit(EXIT_FAILURE);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    addr.sin_addr.s_addr = *(long *)(host->h_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    return sock;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *hostname = argv[1];
    char *port = argv[2];

    init_openssl();
    SSL_CTX *ctx = create_context();

    // Set the callback function for key logging
    SSL_CTX_set_keylog_callback(ctx, ssl_keylog_callback);

    int server = create_socket(hostname, port);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    }

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
