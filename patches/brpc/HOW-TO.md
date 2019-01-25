To build a patched version of brpc 0.9.5, install the dependencies as described
[here](https://github.com/brpc/brpc/blob/master/docs/cn/getting_started.md).
Then install MesaLink 0.8.0 or above at `/usr/`.

```shell
$ curl -LO https://raw.githubusercontent.com/mesalock-linux/mesalink/master/patches/brpc/brpc_0.9.5.patch
$ git clone https://github.com/brpc/brpc.git --branch 0.9.5 && cd brpc
$ patch -p1 < ../brpc_0.9.5.patch
$ sh config_brpc.sh --headers=/usr/include --libs=/usr/lib --with-mesalink
$ make -j
$ cd test && make brpc_ssl_unittest -j && ./brpc_ssl_unittest
```
