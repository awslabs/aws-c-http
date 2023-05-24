# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.
import filecmp
import subprocess
import sys
import urllib.request
import unittest
import os.path

TIMEOUT = 100

# Accepting multiple args so we can pass something like: python elasticurl.py
elasticurl_cmd_prefix = sys.argv[1:]
if not elasticurl_cmd_prefix:
    print('You must pass the elasticurl cmd prefix')
    sys.exit(-1)

program_to_run = elasticurl_cmd_prefix[0]

if 'bin' in program_to_run:
    if not os.path.exists(program_to_run):
        print('the program_to_run is not found, skip integration test')
        sys.exit(0)

# Remove args from sys.argv so that unittest doesn't also try to parse them.
sys.argv = sys.argv[:1]

def run_command(args):
    # gather all stderr and stdout to a single string that we print only if things go wrong
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timedout = False
    try:
        output = process.communicate(timeout=TIMEOUT)[0]
    except subprocess.TimeoutExpired:
        timedout = True
        process.kill()
        args_str = subprocess.list2cmdline(args)
        output = process.communicate()[0]
    finally:
        if process.returncode != 0 or timedout:
            args_str = subprocess.list2cmdline(args)
            print(args_str)
            for line in output.splitlines():
                print(line.decode())
            if timedout:
                raise RuntimeError("Timeout happened after {secs} secs from: {cmd}".format(secs=TIMEOUT, cmd=args_str))
            else:
                raise RuntimeError("Return code {code} from: {cmd}".format(code=process.returncode, cmd=args_str))

def compare_files(filename_expected, filename_other):
    if not filecmp.cmp(filename_expected, filename_other, shallow=False):
        # Give a helpful error message
        with open(filename_expected, 'rb') as expected:
            try:
                bytes_expected = bytearray(expected.read())
            except:
                raise RuntimeError("Failed to open %s" % filename_expected)

        with open(filename_other, 'rb') as other:
            try:
                bytes_other = bytearray(other.read())
            except:
                raise RuntimeError("Failed to open %s" % filename_other)

        if len(bytes_expected) != len(bytes_other):
            raise RuntimeError("File lengths differ. Expected %d, got %d" % (len(bytes_expected), len(bytes_other)))

        for i in range(len(bytes_expected)):
            if bytes_expected[i] != bytes_other[i]:
                raise RuntimeError("Files differ at byte[%d]. Expected %d, got %d." % (i, bytes_expected[i], bytes_other[i]))

        print("filecmp says these files differ, but they are identical. what the heck.")

class SimpleTests(unittest.TestCase):
    def test_simple_get_amazon(self):
        """make a simple GET request via alpn h2;http/1.1 to amazon and make sure it succeeds"""
        simple_get_args = elasticurl_cmd_prefix + ['-v', 'TRACE', 'https://www.amazon.com']
        run_command(simple_get_args)
    def test_simple_get_google(self):
        """make a simple GET request via alpn h2;http/1.1 to google and make sure it succeeds"""
        simple_get_args = elasticurl_cmd_prefix + ['-v', 'TRACE', 'https://www.google.com']
        run_command(simple_get_args)
    def test_simple_get_h1(self):
        """make a simple GET request via HTTP/1.1 and make sure it succeeds"""
        simple_get_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http1_1', 'http://postman-echo.com/get']
        run_command(simple_get_args)

    def test_simple_post_h1(self):
        """make a simple POST request via HTTP/1.1 to make sure sending data succeeds"""
        simple_post_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http1_1', '-P', '-H', 'content-type: application/json', '-i', '-d', '\"{\'test\':\'testval\'}\"', 'http://postman-echo.com/post']
        run_command(simple_post_args)

    def test_simple_download_h1(self):
        """download a large file via HTTP/1.1 and compare the results with something we assume works (e.g. urllib)"""
        elasticurl_download_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http1_1', '-o', 'elastigirl.png', 'https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png']
        run_command(elasticurl_download_args)
        urllib.request.urlretrieve('https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png', 'elastigirl_expected.png')

        compare_files('elastigirl_expected.png', 'elastigirl.png')

    def test_simple_get_h2(self):
        """make a simple GET request via HTTP2 and make sure it succeeds"""
        simple_get_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http2', 'https://postman-echo.com/get']
        run_command(simple_get_args)

    def test_simple_post_h2(self):
        """make a simple POST request via HTTP2 to make sure sending data succeeds"""
        simple_post_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http2', '-P', '-H', 'content-type: application/json', '-i', '-d', '\"{\'test\':\'testval\'}\"', 'https://postman-echo.com/post']
        run_command(simple_post_args)

    def test_simple_download_h2(self):
        """download a large file via HTTP2 and compare the results with something we assume works (e.g. urllib)"""
        elasticurl_download_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http2', '-o', 'elastigirl_h2.png', 'https://d1cz66xoahf9cl.cloudfront.net/elastigirl.png']
        run_command(elasticurl_download_args)
        urllib.request.urlretrieve('https://d1cz66xoahf9cl.cloudfront.net/elastigirl.png', 'elastigirl_expected.png')

        compare_files('elastigirl_expected.png', 'elastigirl_h2.png')

if __name__ == '__main__':
    unittest.main(verbosity=2)
