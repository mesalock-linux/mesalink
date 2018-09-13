To build a patched version of curl 7.61.0, please execute the following after
MesaLink 0.7.1 or above is installed:

```shell
$ curl -LO https://curl.haxx.se/download/curl-7.61.0.tar.gz
$ curl -LO https://raw.githubusercontent.com/mesalock-linux/mesalink/master/patches/curl/curl_7.61.0.patch
$ tar zxvf curl-7.61.0.tar.gz && cd curl-7.61.0
$ patch -p1 < ../curl_7.61.0.patch
$ autoreconf
$ ./configure --with-mesalink --without-ssl --enable-warnings --enable-werrors
$ make
$ sh curl-config --ssl-backends
```

Starting from 09/13/2018, MesaLink is accepted as a builtin TLS backend in curl. We suggest users switch to the built-in MesaLink backend in the upcoming curl releases.
