# Caesar cipher provider for OpenSSL

Toy example of an OpenSSL provider

## How to compile

```
make
```

Creates `caesar.so` library.


## How to verify the compilation

```
OPENSSL_MODULES=. openssl list -verbose -providers -provider caesar
OPENSSL_MODULES=. openssl list -verbose -providers -provider caesar -cipher-algorithms
```

You might need to export `LD_LIBRARY_PATH` set to the location of libcrypto beforehand (e.g. `export LD_LIBRARY_PATH=/usr/local/lib64`).

## Encryption and decryption

Default provider and pbkdf2 needed for some functionality, e.g. key derivation.

Encrypt `plain.txt`:

```
OPENSSL_MODULES=. openssl enc -caesar -pbkdf2 -nosalt -provider caesar -provider default -in plain.txt -out cipher.txt
```

Decrypt `cipher.txt` to `decrypted.txt`:
```
OPENSSL_MODULES=. openssl enc -d -caesar -pbkdf2 -nosalt -provider caesar -provider default -in cipher.txt -out decrypted.txt
```

## Debugging

For debugging with valgrind/gdb, both the provider and openssl must be compiled with debug info (`-g` and `--debug` respectively). Remember to use the dev version instead of the system installation (e.g. `../openssl/apps/openssl enc` instead of `openssl enc`).