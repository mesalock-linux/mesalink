#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <mesalink/openssl/ssl.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "mesalink.lib")

#define DEFAULT_BUFLEN 8192
#define DEFAULT_PORT "443"

#define REQUEST                                                               \
  "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nAccept-Encoding: "      \
  "identity\r\n\r\n"

int __cdecl main(int argc, char **argv)
{
  SSL_CTX *ctx;
  SSL *ssl;

  WSADATA wsaData;
  SOCKET ConnectSocket = INVALID_SOCKET;
  struct addrinfo *result = NULL, *ptr = NULL, hints;
  char sendbuf[DEFAULT_BUFLEN] = { 0 };
  char recvbuf[DEFAULT_BUFLEN] = { 0 };
  int iResult;
  int recvbuflen = DEFAULT_BUFLEN;

  // Validate the parameters
  if(argc != 2) {
    printf("usage: %s server-name\n", argv[0]);
    return 1;
  }

  // Initialize MesaLink
  ctx = SSL_CTX_new(SSLv23_client_method());
  ssl = SSL_new(ctx);
  char hostname_buf[256] = { 0 };
  strncpy_s(hostname_buf, argv[1], strlen(argv[1]));
  SSL_set_tlsext_host_name(ssl, hostname_buf);

  // Initialize Winsock
  iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if(iResult != 0) {
    printf("WSAStartup failed with error: %d\n", iResult);
    return 1;
  }

  ZeroMemory(&hints, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  // Resolve the server address and port
  iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
  if(iResult != 0) {
    printf("getaddrinfo failed with error: %d\n", iResult);
    WSACleanup();
    return 1;
  }

  // Attempt to connect to an address until one succeeds
  for(ptr = result; ptr != NULL; ptr = ptr->ai_next) {

    // Create a SOCKET for connecting to server
    ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if(ConnectSocket == INVALID_SOCKET) {
      printf("socket failed with error: %ld\n", WSAGetLastError());
      WSACleanup();
      return 1;
    }

    // Connect to server.
    iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
    if(iResult == SOCKET_ERROR) {
      closesocket(ConnectSocket);
      ConnectSocket = INVALID_SOCKET;
      continue;
    }
    break;
  }

  freeaddrinfo(result);

  if(ConnectSocket == INVALID_SOCKET) {
    printf("Unable to connect to server!\n");
    WSACleanup();
    return 1;
  }

  SSL_set_socket(ssl, ConnectSocket);
  if(SSL_connect(ssl) == SSL_SUCCESS) {
    int sendlen = -1, recvlen = -1;
    size_t total_recvlen = 0;
    int cipher_bits = 0;
    SSL_get_cipher_bits(ssl, &cipher_bits);
    printf("[+] Negotiated ciphersuite: %s, enc_length=%d, version=%s\n",
           SSL_get_cipher_name(ssl),
           cipher_bits,
           SSL_get_cipher_version(ssl));

    snprintf(sendbuf, sizeof(sendbuf), REQUEST, hostname_buf);
    sendlen = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
    printf("[+] Sent %d bytes\n\n%s\n", sendlen, sendbuf);

    while((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1)) > 0) {
      recvbuf[recvlen] = 0;
      total_recvlen += strlen(recvbuf);
      printf("%s", recvbuf);
    };
  }

  // cleanup
  closesocket(ConnectSocket);
  WSACleanup();

  if(ssl)
    SSL_free(ssl);
  if(ctx)
    SSL_CTX_free(ctx);

  return 0;
}