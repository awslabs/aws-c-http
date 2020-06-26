## AWS C Http

C99 implementation of the HTTP/1.1 and HTTP/2 specifications

## License

This library is licensed under the Apache 2.0 License.

## Usage

#### Building s2n (Linux Only)

If you are building on Linux, you will need to build s2n before being able to build aws-c-io, which is a dependency for aws-c-http.  For our CRT's, we build s2n at a specific commit, and recommend doing the same when using it with this library.  That commit hash can be found [here](https://github.com/awslabs/aws-crt-cpp/tree/master/aws-common-runtime).  The commands below will build s2n using OpenSSL 1.1.1.  For using other versions of OpenSSL, there is additional information in the [s2n Usage Guide](https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md).

```
git clone git@github.com:awslabs/s2n.git
cd s2n
git checkout <s2n-commit-hash-used-by-aws-crt-cpp>

# We keep the build artifacts in the -build directory
cd libcrypto-build

# Download the latest version of OpenSSL
curl -LO https://www.openssl.org/source/openssl-1.1.1-latest.tar.gz
tar -xzvf openssl-1.1.1-latest.tar.gz

# Build openssl libcrypto.  Note that the install path specified here must be absolute.
cd `tar ztf openssl-1.1.1-latest.tar.gz | head -n1 | cut -f1 -d/`
./config -fPIC no-shared              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=<absolute-install-path>
make
make install

# Build s2n
cd ../../../
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S s2n -B s2n/build
cmake --build s2n/build --target install
```

#### Building aws-c-http and Remaining Dependencies

Note that aws-c-http has several dependencies that need to be built.

```
git clone git@github.com:awslabs/aws-c-common.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-common -B aws-c-common/build
cmake --build aws-c-common/build --target install

git clone git@github.com:awslabs/aws-c-io.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-io -B aws-c-io/build
cmake --build aws-c-io/build --target install

git clone git@github.com:awslabs/aws-c-compression.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-compression -B aws-c-compression/build
cmake --build aws-c-compression/build --target install

git clone git@github.com:awslabs/aws-c-http.git
cmake -DCMAKE_PREFIX_PATH=<install-path> -DCMAKE_INSTALL_PREFIX=<install-path> -S aws-c-http -B aws-c-http/build
cmake --build aws-c-http/build --target install
```
