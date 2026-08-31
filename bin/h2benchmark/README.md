# HTTP/2 benchmark

this is a C program mimic the API call benchmark from aws-java-sdk-v2. https://github.com/aws/aws-sdk-java-v2/tree/master/test/sdk-benchmarks/src/main/java/software/amazon/awssdk/benchmark/apicall/httpclient

It collects how many API calls finish per second. Basically how many request can made per second.

The program connects to the local host that can be found [here](../../tests/mock_server).

To run the benchmark, build the h2benchmark with aws-c-http as dependency.

## Configuration

Run `h2benchmark --help` for the full list. The defaults match what CI uses, so no arguments are needed for a
standard run. The available options are:

| Option | Description | Default |
| --- | --- | --- |
| `-u, --uri` | URI to benchmark against | `http://localhost:3280/` |
| `-r, --rate-secs` | Seconds per measurement interval | 30 |
| `-s, --streams-per-connection` | Max concurrent streams per connection | 20 |
| `-c, --max-connections` | Max connections | 8 |
| `-n, --num-loops` | Number of intervals to measure | 5 |
| `-t, --rate-threshold` | Fail if streams/sec averages below this | 4000 |
| `-l, --log-level` | 0=none 1=fatal 2=error 3=warn 4=info 5=debug 6=trace | 0 |
| `-d, --direct-connection` | Use a single connection instead of the stream manager | off |

The process exits non-zero if the average streams/sec falls below `--rate-threshold`, which is what makes it usable
as a regression check. On a slow machine you may need to lower that threshold.
