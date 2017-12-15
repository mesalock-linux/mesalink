/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017, The MesaLink Authors. 
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

/* This example demonstrates the OpenSSL compatibility layer */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <mesalink/openssl/ssl.h>
#include <mesalink/openssl/err.h>

int main(int argc, char *argv[])
{
    int sockfd, port;
    struct sockaddr_in addr;
    char recvbuf[1024] = {0};
    const char *cert_file;
    const char *key_file;
    const char *response = "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n<html><body><pre>Hello from MesaLink server</pre></body></html>\r\n";

    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (argc != 4)
    {
        printf("Usage: %s <portnum> <cert_file> <private_key_file>\n", argv[0]);
        exit(0);
    }
    port = atoi(argv[1]);
    cert_file = argv[2];
    key_file = argv[3];

    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (ctx == NULL)
    {
        fprintf(stderr, "[-] Context failed to create\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "[-] Failed to load cetificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "[-] Failed to load private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "[-] Certificate and private key mismatch\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        fprintf(stderr, "[-] Accept error\n");
        return -1;
    }
    fprintf(stdout, "[+] Listening at 0.0.0.0:%d\n", port);
    if (listen(sockfd, 10) != 0)
    {
        fprintf(stderr, "[-] Listen error\n");
        return -1;
    }
    while (1)
    {
        SSL *ssl;
        unsigned int len = sizeof(addr);
        int client_sockfd = accept(sockfd, (struct sockaddr *)&addr, &len);
        ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            fprintf(stderr, "[-] SSL creation failed\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
        if (SSL_set_fd(ssl, client_sockfd) != SUCCESS)
        {
            fprintf(stderr, "[-] SSL set fd failed\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
        if (SSL_accept(ssl) == SUCCESS)
        {
            int recvlen = -1;
            while ((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1)) > 0)
            {
                recvbuf[recvlen] = 0;
                printf("[+] Received:\n%s", recvbuf);
                SSL_write(ssl, response, strlen(response));
            }
        }
        else
        {
            fprintf(stderr, "[-] Socket not accepted");
            ERR_print_errors_fp(stderr);
        }
        client_sockfd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(client_sockfd);
    }
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
