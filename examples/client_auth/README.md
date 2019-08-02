
### Run OpenSSL server

```shell
$ openssl s_server -accept 8400 -cert end.fullchain -key end.key -Verify 10 -CAfile client.fullchain
```

### Test OpenSSL client

```shell
$ openssl s_client -connect 127.0.0.1:8400 -cert client.fullchain -key client.key -CAfile ca.cert
```

### Compile the MeasLink client

```shell
$ gcc client_auth.c -o client_auth -lmesalink
```

### Test it!

```shell
$ ./client_auth localhost 8400
```
