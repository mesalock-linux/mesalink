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

#define REQUEST                                                               \
  "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nAccept-Encoding: "      \
  "identity\r\n\r\n"

int tls_client(SSL_CTX *, const char *);

int
tls_client(SSL_CTX *ctx, const char *hostname)
{
  SSL *ssl = NULL;
  int sockfd = -1;
  struct hostent *hp;
  struct sockaddr_in addr;
  char sendbuf[8192] = { 0 };
  char recvbuf[8192] = { 0 };

  if((hp = gethostbyname(hostname)) == NULL) {
    fprintf(stderr, "[-] Gethostname error\n");
    goto fail;
  }
  memset(&addr, 0, sizeof(addr));
  memmove(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(443);
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
  char hostname_buf[256] = { 0 };
  strncpy(hostname_buf, hostname, strlen(hostname));
  if(SSL_set_tlsext_host_name(ssl, hostname_buf) != SSL_SUCCESS) {
    fprintf(stderr, "[-] Failed to set hostname\n");
    goto fail;
  }
  if(SSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
    fprintf(stderr, "[-] Faield to set fd\n");
    goto fail;
  }
  if(SSL_connect(ssl) == SSL_SUCCESS) {
    int sendlen = -1, recvlen = -1, total_recvlen = 0;
    int cipher_bits = 0;
    SSL_get_cipher_bits(ssl, &cipher_bits);
    printf("[+] Negotiated ciphersuite: %s, enc_length=%d, version=%s\n",
           SSL_get_cipher_name(ssl),
           cipher_bits,
           SSL_get_cipher_version(ssl));

    char name_buf[253] = { 0 };
    X509 *cert = SSL_get_peer_certificate(ssl);

    X509_NAME *subject_name = X509_get_subject_name(cert);
    printf("[+] Subject name: %s\n", X509_NAME_oneline(subject_name, name_buf, 253));
    memset(name_buf, 0, 253);

    STACK_OF(X509_NAME) *names = X509_get_alt_subject_names(cert);
    int length = sk_X509_NAME_num(names);
    printf("[+] Subject alternative names:");
    for(int i = 0; i < length; i++) {
      X509_NAME *name = sk_X509_NAME_value(names, i);
      printf("%s, ", X509_NAME_oneline(name, name_buf, 253));
    }
    printf("\n");
    sk_X509_NAME_free(names);
    X509_free(cert);

    snprintf(sendbuf, sizeof(sendbuf), REQUEST, hostname);
    sendlen = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
    printf("[+] Sent %d bytes\n\n%s\n", sendlen, sendbuf);

    while((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1)) > 0) {
      recvbuf[recvlen] = 0;
      total_recvlen += strlen(recvbuf);
      printf("%s", recvbuf);
    };
    if(total_recvlen > 0) {
      const char *tls_version;
      if((tls_version = SSL_get_version(ssl))) {
        printf("[+] TLS protocol version: %s\n", tls_version);
      }

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
main(int argc, char *argv[])
{

  const char *hostname;
  SSL_CTX *ctx;

  if(argc != 2) {
    printf("Usage: %s <hostname>\n", argv[0]);
    exit(0);
  }
  hostname = argv[1];
  SSL_library_init();
  ERR_load_crypto_strings();
  // SSL_load_error_strings(); // Uncomment this line to see SSL logs

  ctx = SSL_CTX_new(TLSv1_2_client_method());
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);

  if(ctx == NULL) {
    fprintf(stderr, "[-] Failed to create SSL_CTX\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }
  // fresh start
  tls_client(ctx, hostname);
  // session resumption
  tls_client(ctx, hostname);
  SSL_CTX_free(ctx);
  return 0;
}
