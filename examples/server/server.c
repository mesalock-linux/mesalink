/* server.c
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
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void Servlet(SSL* ssl)    /* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* message = "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n<html><body><pre>Hello from Mesalink server</pre></body></html>\r\n";

    if ( SSL_accept(ssl) == FAIL ) {                  /* do SSL-protocol accept */
        printf("Failed to accept\n");
        ERR_print_errors_fp(stderr);
    } else {
        ShowCerts(ssl);                                /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf));    /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, message, buf);            /* construct reply */
            SSL_write(ssl, reply, strlen(reply));    /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);                            /* get socket connection */
    SSL_free(ssl);                                    /* release SSL state */
    close(sd);                                        /* close connection */
}

int main(int argc, char *argv[]) {   
    int sockfd, port;
    struct sockaddr_in addr;
    char sendbuf[1024] = {0};
    char recvbuf[1024] = {0};
    const char* cert_file, key_file;
    const char* response = "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n<html><body><pre>Hello from Mesalink server</pre></body></html>\r\n";

    SSL_METHOD *method;
    SSL_CTX *ctx;

    if (argc != 4) {
        printf("Usage: %s <portnum> <cert_file> <private_key_file>\n", argv[0]);
        exit(0);
    }
    port = atoi(argv[1]);
    cert_file = argv[2];
    key_file = argv[3];

    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    method = SSLv23_server_method();
    if (method == NULL) {
        fprintf(stderr, "[-] Method is NULL\n");
        return -1;
    }
    ctx = SSL_CTX_new(method);            /* create new context from method */
    if (ctx == NULL) {
        fprintf(stderr, "[-] Context failed to create\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[-] Failed to load cetificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[-] Failed to load private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[-] Certificate and private key mismatch\n");
        return -1;
    }

    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        sprintf(stderr, "[-] Accept error\n");
        return -1;
    }
    if (listen(sockfd, 10) != 0) {
        sprintf(stderr, "[-] Listen error\n");
        return -1;
    }

    while (1) {
        SSL *ssl;
        unsigned int len = sizeof(addr);
        int client = accept(server, (struct sockaddr *) &addr, &len);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        
        if (SSL_accept(ssl) != SSL_SUCCESS ) {
            sprintf(stderr, "[-] Socket not accepted");
            ERR_print_errors_fp(stderr);
            break;
        } else {
            int sendlen = -1, recvlen = -1, total_recv_len = 0;
            while ((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1) > 0) {
                recvbuf[recvlen] = 0;
                total_recv_len += strlen(recvbuf);
                printf("%s", recvbuf);
                SSL_write(ssl, response, strlen(response));
            }
            printf("\n[+] Received %d bytes\n", total_recv_len);
        }
        client_sockfd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(client_sockfd);             
    }
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
