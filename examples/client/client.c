/* ssh.h
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

int main(void) {
    int ret;
    int sockfd;
    struct hostent *hp;
    struct sockaddr_in addr;
    char sendbuf[1024] = {0};
    char recvbuf[1024] = {0};
    const char *request = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n";

    SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;

    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        printf("[-] Error: context failed to create\n");
        return -1;
    }

    if ((hp = gethostbyname("google.com")) == NULL) {
        printf("[-] Gethostname error\n");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == connect(sockfd, (struct sockaddr *) &addr, sizeof(addr))) {
        printf("[-] Connect error\n");
        return -1;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("[-] SSL creation failed\n");
    }
    if (SSL_set_fd(ssl, sockfd) < 0) {
        printf("[-] SSL set fd failed\n");
        return -1;
    }
    if (SSL_connect(ssl) < 0) {
        printf("[-] Socket not connected");
        return -1;
    } else {
        int sendlen, recvlen;
        sprintf(sendbuf, request, "google.com");
        //printf("[+] Connected with %s cipher suites\n", mesalink_get_cipher(ssl));
        sendlen = SSL_write(ssl, sendbuf, strlen(sendbuf));
        printf("[+] Sent %d bytes\n\n%s\n", sendlen, sendbuf);
        recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf));
        recvbuf[recvlen] = 0;
        printf("[+] Received %ld bytes\n\n%s\n\n", strlen(recvbuf), recvbuf);
        SSL_free(ssl);
    }
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
