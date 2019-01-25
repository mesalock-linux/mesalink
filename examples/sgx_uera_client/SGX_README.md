## SGX Remote Attestation for Untrusted Enclaves

Intel(R) Software Guard Extensions (Intel SGX) is a promising technology to
securely process information in isolated memory areas, or *enclaves*. Before a
client can connect to an untrusted remote SGX enclave, the client needs to
perform remote attestation over TLS to assess the enclave's trustworthiness.
This requires a slightly different certificate verification scheme from that of
TLS. The design of the new scheme can be found in this
[whitepaper](https://github.com/cloud-security-research/sgx-ra-tls/blob/master/whitepaper.pdf).

Starting from 0.8.0, MesaLink has included experimental support for SGX remote
attestation. This can be enabled by passing `--enable-sgx` to `configure`. An
example is included in `examples/sgx_uera_client`. A precompiled enclave
targeting x86_64 Linux is provided in
`examples/sgx_uera_client/sgx_enclave_server`, which is just a copy of Rust SGX
SDK's [ue-ra
example](https://github.com/baidu/rust-sgx-sdk/tree/master/samplecode/ue-ra/ue-ra-server).

To run the example, please follow these steps:

0. Make sure your CPU supports SGX and `/dev/isgx` exists.

1. Compile MesaLink with examples and SGX support.
```shell
# ./configure --enable-sgx --enable-examples
# make

```

2. Run the enclave. The enclaves listens at localhost:3443.
```shell
# cd examples/sgx_uera_client/sgx_enclave_server
# ./app
```

3. Run the client.
```shell
# cd examples/sgx_uera_client
# ./sgx_uera_client
```

For more details, please also refer to the [Rust SGX SDK project](https://github.com/baidu/rust-sgx-sdk/blob/master/samplecode/ue-ra/Readme.md).
