## ElastiCurl
This is a sample application showing how to use `aws-c-http` in client mode. It's intended to replicate the command-line interface of curl's http support.

### Usage
### Examples
Dump the body of example.com to stdout

    elasticurl example.com
    
Make a POST request with a header and payload, logging ERROR and FATAL messages:

    elasticurl -v ERROR -P -H "content-type: application/json" -i -d "{'test':'testval'}" http://httpbin.org/post
    
Download an http resource to a file on disk, logging INFO, WARN, ERROR, and FATAL messages:  

    elasticurl -v INFO -o elastigirl.png https://upload.wikimedia.org/wikipedia/en/thumb/e/ef/Helen_Parr.png/220px-Helen_Parr.png
    
### Command Line Interface
elasticurl [options] url

Note: https is always the default. If you want plain-text http, either specify `http` manually, or set ports `80` or `8080` 

#### Options 
##### --cacert  
Path to a PEM Armored PKCS#7 CA Certificate file.
##### --capath
Path to a directory containing ca certificates (only supported on Unix systems).
##### --cert
Path for a certificate to use with mTLS. Usually this is a path to a PEM armored PKCS#7 file.
On windows this can also be a registry path for certificate manager.
##### --key   
Key corresponding to `--cert`. Usually this is a path to a PEM armored PKCS#7 file, if using a certificate manager
registry path for `--cert`, this should be empty.
##### --connect-timeout
Amount of time to wait for a connection. The default value is 3000 (3 seconds). This value is specified in milliseconds.
##### -H, --header
Line to send as a header in format `[header-key]: [header-value]`. This option can be specified multiple times. The max
number of supported values is currently 10.
##### -d, --data
String to send as the payload body for a POST or PUT method.
##### --data-file
Path to a file to send as the payload body for a POST or PUT method.
##### -M, --method
Http method to use for the request (e.g. GET, POST, PUT, DELETE etc...). GET is the default.
##### -G, --get 
Uses GET as the method for the http request.
##### -P, --post
Uses POST as the method for the http request.
##### -I, --head
Uses HEAD as the method for the http request.
##### -i, --include
Includes the response headers in the output to stdout.
##### -k, --insecure
Turns off TLS certificate validation.
##### -o, --output
Sends the response body to the path specified instead of stdout.
##### -t, --trace
Sends log message to the path specified instead of stderr.
##### -v, --verbose
Sets the verbosity level of logs. Options are: ERROR|INFO|DEBUG|TRACE. Default is no logging. If you set this option,
without the `--trace` argument, logs will be written to stderr.
##### -h, --help
Displays the help message and exits the program.
