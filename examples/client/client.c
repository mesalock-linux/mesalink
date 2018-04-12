/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017-2018, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#include <fcntl.h>
#include <mesalink/openssl/err.h>
#include <mesalink/openssl/ssl.h>
#include <mesalink/openssl/x509.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUEST                                                                \
    "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nAccept-Encoding: "     \
    "identity\r\n\r\n"

int main(int argc, char *argv[]) {
    int sockfd;
    struct hostent *hp;
    struct sockaddr_in addr;
    char sendbuf[8192] = {0};
    char recvbuf[8192] = {0};
    const char *hostname;
    SSL_CTX *ctx;
    SSL *ssl;
    if (argc != 2) {
        printf("Usage: %s <hostname>\n", argv[0]);
        exit(0);
    }
    hostname = argv[1];
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "[-] Context failed to create\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if ((hp = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "[-] Gethostname error\n");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    memmove(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[-] Connect error\n");
        return -1;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "[-] SSL creation failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    char *hostname_buf = malloc(256 * sizeof(char));
    strncpy(hostname_buf, hostname, strlen(hostname));

    if (SSL_set_tlsext_host_name(ssl, hostname_buf) != SSL_SUCCESS) {
        fprintf(stderr, "[-] SSL set hostname failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    free(hostname_buf);

    if (SSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        fprintf(stderr, "[-] SSL set fd failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_connect(ssl) == SSL_SUCCESS) {
        int sendlen = -1, recvlen = -1, total_recvlen = 0;

        int cipher_bits = 0;
        SSL_get_cipher_bits(ssl, &cipher_bits);
        printf("[+] Negotiated ciphersuite: %s, enc_length=%d, version=%s\n",
               SSL_get_cipher_name(ssl), cipher_bits,
               SSL_get_cipher_version(ssl));

        X509 *cert = SSL_get_peer_certificate(ssl);
        STACK_OF(X509_NAME) *names = X509_get_alt_subject_names(cert);
        int length = sk_X509_NAME_num(names);
        char *name_buf = malloc(128 * sizeof(char));
        for (int i = 0; i < length; i++) {
            X509_NAME *name = sk_X509_NAME_value(names, i);
            printf("[+] Alterantive subject name: %s\n",
                   X509_NAME_oneline(name, name_buf, 128));
        }

        snprintf(sendbuf, sizeof(sendbuf), REQUEST, hostname);
        sendlen = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
        printf("[+] Sent %d bytes\n\n%s\n", sendlen, sendbuf);

        while ((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1)) !=
               SSL_FAILURE) {
            recvbuf[recvlen] = 0;
            total_recvlen += strlen(recvbuf);
            printf("%s", recvbuf);
        };
        if (total_recvlen > 0) {
            const char *tls_version;
            if ((tls_version = SSL_get_version(ssl))) {
                printf("[+] TLS protocol version: %s\n", tls_version);
            }

            printf("\n[+] Received %d bytes\n", total_recvlen);
            SSL_free(ssl);
        } else {
            fprintf(stderr, "[-] Got nothing\n");
        }
    } else {
        fprintf(stderr, "[-] Socket not connected\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ERR_print_errors_fp(stderr);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
