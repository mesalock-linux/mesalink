/* client.c
 *                            _ _       _    
 *                           | (_)     | |   
 *  _ __ ___   ___  ___  __ _| |_ _ __ | | __
 * | '_ ` _ \ / _ \/ __|/ _` | | | '_ \| |/ /
 * | | | | | |  __/\__ \ (_| | | | | | |   < 
 * |_| |_| |_|\___||___/\__,_|_|_|_| |_|_|\_\
 *
 * Copyright (C) 2017 Baidu USA.
 *
 * This file is part of Mesalink.
 */

 /* This example demonstrates the OpenSSL compatibility layer */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <mesalink/openssl/ssl.h>
#include <mesalink/openssl/err.h>

int main(int argc, char *argv[]) {
    int sockfd;
    struct hostent *hp;
    struct sockaddr_in addr;
    char sendbuf[1024] = {0};
    char recvbuf[1024] = {0};
    const char *hostname;
    const char *request = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n";

    SSL_METHOD *method;
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

    method = TLSv1_2_client_method();
    if (method == NULL) {
        sprintf(stderr, "[-] Method is NULL\n");
        return -1;
    }
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        sprintf(stderr, "[-] Context failed to create\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if ((hp = gethostbyname(hostname)) == NULL) {
        sprintf(stderr, "[-] Gethostname error\n");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        sprintf(stderr, "[-] Connect error\n");
        return -1;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        sprintf(stderr, "[-] SSL creation failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_set_tlsext_host_name(ssl, hostname) < 0) {
        sprintf(stderr, "[-] SSL set hostname failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        sprintf(stderr, "[-] SSL set fd failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_connect(ssl) != SSL_SUCCESS) {
        sprintf(stderr, "[-] Socket not connected");
        ERR_print_errors_fp(stderr);
        return -1;
    } else {
        int sendlen = -1, recvlen = -1, total_recv_len = 0;
        sprintf(sendbuf, request, hostname);
        //printf("[+] Connected with %s cipher suites\n", mesalink_get_cipher(ssl));
        sendlen = SSL_write(ssl, sendbuf, strlen(sendbuf));
        printf("[+] Sent %d bytes\n\n%s\n", sendlen, sendbuf);
        while ((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1)) > 0) {
            recvbuf[recvlen] = 0;
            total_recv_len += strlen(recvbuf);
            printf("%s", recvbuf);
        };
        printf("\n[+] Received %d bytes\n", total_recv_len);
        SSL_free(ssl);
    }
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
