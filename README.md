## AWS C Http

C99 implementation of the HTTP/1.1 and HTTP/2 specifications

## License

This library is licensed under the Apache 2.0 License.

## Usage

### Building

Note that aws-c-http has several dependencies.  If you are building on Linux, you will also need to build s2n before being able to build aws-c-io.  Build instructions for s2n can be found [here](https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md).  For our CRT's, we build s2n at a specific commit, and recommend doing the same when using it with this library.  That commit hash can be found [here](https://github.com/awslabs/aws-crt-cpp/tree/master/aws-common-runtime).

````
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
````
