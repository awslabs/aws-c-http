# Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
import filecmp
import subprocess
import sys
import urllib.request
import unittest

# Accepting multiple args so we can pass something like: python elasticurl.py
elasticurl_cmd_prefix = sys.argv[1:]
if not elasticurl_cmd_prefix:
    print('You must pass the elasticurl cmd prefix')
    sys.exit(-1)

# Remove args from sys.argv so that unittest doesn't also try to parse them.
sys.argv = sys.argv[:1]

def run_command(args):
    # gather all stderr and stdout to a single string that we print only if things go wrong
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = process.communicate()[0]

    if process.returncode != 0:
        args_str = subprocess.list2cmdline(args)
        print(args_str)
        for line in output.splitlines():
            print(line.decode())

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
    def test_simple_get_h1(self):
        """make a simple GET request via HTTP/1.1 and make sure it succeeds"""
        simple_get_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http1_1', 'http://example.com']
        run_command(simple_get_args)

    def test_simple_post_h1(self):
        """make a simple POST request via HTTP/1.1 to make sure sending data succeeds"""
        simple_post_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http1_1', '-P', '-H', 'content-type: application/json', '-i', '-d', '\"{\'test\':\'testval\'}\"', 'http://httpbin.org/post']
        run_command(simple_post_args)

    def test_simple_download_h1(self):
        """download a large file via HTTP/1.1 and compare the results with something we assume works (e.g. urllib)"""
        elasticurl_download_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http1_1', '-o', 'elastigirl.png', 'https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png']
        run_command(elasticurl_download_args)
        urllib.request.urlretrieve('https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png', 'elastigirl_expected.png')

        compare_files('elastigirl_expected.png', 'elastigirl.png')

    def test_simple_get_h2(self):
        """make a simple GET request via HTTP2 and make sure it succeeds"""
        simple_get_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http2', 'https://example.com']
        run_command(simple_get_args)

    def test_simple_post_h2(self):
        """make a simple POST request via HTTP2 to make sure sending data succeeds"""
        simple_post_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http2', '-P', '-H', 'content-type: application/json', '-i', '-d', '\"{\'test\':\'testval\'}\"', 'https://httpbin.org/post']
        run_command(simple_post_args)

    def test_simple_download_h2(self):
        """download a large file via HTTP2 and compare the results with something we assume works (e.g. urllib)"""
        elasticurl_download_args = elasticurl_cmd_prefix + ['-v', 'TRACE', '--http2', '-o', 'elastigirl_h2.png', 'https://d1cz66xoahf9cl.cloudfront.net/elastigirl.png']
        run_command(elasticurl_download_args)
        urllib.request.urlretrieve('https://d1cz66xoahf9cl.cloudfront.net/elastigirl.png', 'elastigirl_expected.png')

        compare_files('elastigirl_expected.png', 'elastigirl_h2.png')

if __name__ == '__main__':
    unittest.main(verbosity=2)
