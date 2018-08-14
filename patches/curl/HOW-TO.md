To build a patched version of curl 7.61.0, please execute the following after
MesaLink 0.7.0 or above is installed:

```shell
$ curl -LO https://curl.haxx.se/download/curl-7.61.0.tar.gz
$ curl -LO https://raw.githubusercontent.com/mesalock-linux/mesalink/master/patches/curl/curl_7.61.0.patch
$ tar zxvf curl-7.61.0.tar.gz && cd curl-7.61.0
$ patch -p1 < ../curl_7.61.0.patch
$ autoreconf
$ ./configure --with-mesalink --without-ssl
$ make
$ sh curl-config --ssl-backends
```
