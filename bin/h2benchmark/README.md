# HTTP/2 benchmark

this is a C program mimic the API call benchmark from aws-java-sdk-v2. https://github.com/aws/aws-sdk-java-v2/tree/master/test/sdk-benchmarks/src/main/java/software/amazon/awssdk/benchmark/apicall/httpclient

It collects how many API calls finish per second. Basically how many request can made per second.

The program connects to the local host that can be found [here](../../tests/py_localhost).

To run the benchmark, build the h2benchmark with aws-c-http as dependency.
TODO: Currently the configs are all hardcoded.
