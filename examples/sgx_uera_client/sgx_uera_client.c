/*
 *   __  __                 _     _       _
 *  |  \/  | ___  ___  __ _| |   (_)_ __ | | __
 *  | |\/| |/ _ \/ __|/ _` | |   | | '_ \| |/ /
 *  | |  | |  __/\__ \ (_| | |___| | | | |   <
 *  |_|  |_|\___||___/\__,_|_____|_|_| |_|_|\_\
 *
 * Copyright (c) 2017-2019, The MesaLink Authors.
 * All rights reserved.
 *
 * This work is licensed under the terms of the BSD 3-Clause License.
 * For a copy, see the LICENSE file.
 *
 */

#include <fcntl.h>
#include <mesalink/openssl/err.h>
#include <mesalink/openssl/ssl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int
sgx_uera_tls_client(SSL_CTX *ctx, const char *hostname, int port)
{
  SSL *ssl = NULL;
  int sockfd = -1;
  struct hostent *hp;
  struct sockaddr_in addr;
  char sendbuf[1024] = { 0 };
  char recvbuf[1024] = { 0 };

  if((hp = gethostbyname("localhost")) == NULL) {
    fprintf(stderr, "[-] Gethostname error\n");
    goto fail;
  }
  memset(&addr, 0, sizeof(addr));
  memmove(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    fprintf(stderr, "[-] Connect error\n");
    goto fail;
  }
  ssl = SSL_new(ctx);
  if(ssl == NULL) {
    fprintf(stderr, "[-] Failed to create SSL\n");
    ERR_print_errors_fp(stderr);
    goto fail;
  }
  if(SSL_set_tlsext_host_name(ssl, hostname) != SSL_SUCCESS) {
    fprintf(stderr, "[-] Failed to set hostname\n");
    goto fail;
  }
  if(SSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
    fprintf(stderr, "[-] Faield to set fd\n");
    goto fail;
  }
  if(SSL_connect(ssl) == SSL_SUCCESS) {
    int sendlen = -1, recvlen = -1, total_recvlen = 0;

    snprintf(sendbuf, sizeof(sendbuf), "hello");
    sendlen = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
    printf("[+] Sent %d bytes\n\n%s\n", sendlen, sendbuf);

    while((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1)) > 0) {
      recvbuf[recvlen] = 0;
      total_recvlen += strlen(recvbuf);
      printf("%s", recvbuf);
    };
    if(total_recvlen > 0) {
      printf("\n[+] Received %d bytes\n", total_recvlen);
    }
    else {
      fprintf(stderr, "[-] Got nothing\n");
    }
  }
  else {
    fprintf(stderr, "[-] Socket not connected\n");
    fprintf(stderr, "[-] SSL error code: 0x%x\n", SSL_get_error(ssl, -1));
    ERR_print_errors_fp(stderr);
    goto fail;
  }
fail:

  if(ssl) {
    SSL_free(ssl);
  }
  if(!sockfd) {
    close(sockfd);
  }
  return -1;
}

int
main()
{
  SSL_CTX *ctx;
  ctx = SSL_CTX_new(SSLv23_client_method());
  char mr_signer[32] = { 0x83, 0xd7, 0x19, 0xe7, 0x7d, 0xea, 0xca, 0x14,
                         0x70, 0xf6, 0xba, 0xf6, 0x2a, 0x4d, 0x77, 0x43,
                         0x03, 0xc8, 0x99, 0xdb, 0x69, 0x02, 0x0f, 0x9c,
                         0x70, 0xee, 0x1d, 0xfc, 0x08, 0xc7, 0xce, 0x9e };
  SSL_CTX_set_sgx_verify(ctx,
                         mr_signer,
                         SGX_FLAGS_DEBUG | SGX_ALLOW_CONFIGURATION_NEEDED |
                           SGX_ALLOW_GROUP_OUT_OF_DATE);
  sgx_uera_tls_client(ctx, "localhost", 3443);
  SSL_CTX_free(ctx);
  return 0;
}
