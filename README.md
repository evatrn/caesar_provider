# Caesar cipher provider for OpenSSL

Toy example of an OpenSSL provider

## How to compile

```
make
```

Creates caesar.so library.


## How to verify the compilation

```
OPENSSL_MODULES=. openssl list -verbose -providers -provider caesar
OPENSSL_MODULES=. openssl list -verbose -providers -provider caesar -cipher-algorithms
```

You might need to export `LD_LIBRARY_PATH` set to the location of libcrypto beforehand (e.g. `export LD_LIBRARY_PATH=/usr/local/lib64`).

