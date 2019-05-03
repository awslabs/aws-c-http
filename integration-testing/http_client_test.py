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

elasticurl_path = sys.argv.pop()
shell = sys.platform.startswith('win')

if elasticurl_path == None:
    print("You must pass the path to elasticurl as the first argument.")
    sys.exit(-1)

def run_command(args):
    subprocess.check_call(args, shell=shell)


class SimpleTests(unittest.TestCase):
#make a simple GET request and make sure it succeeds
    def test_simple_get(self):
        simple_get_args = [elasticurl_path, '-v', 'TRACE', 'http://example.com']
        run_command(simple_get_args)

#make a simple POST request to make sure sending data succeeds
    def test_simple_post(self):
        simple_post_args = [elasticurl_path, '-v', 'TRACE', '-P', '-H', 'content-type: application/json', '-i', '-d', '\"{\'test\':\'testval\'}\"', 'http://httpbin.org/post']
        run_command(simple_post_args)

#download a large file and compare the results with something we assume works (e.g. urllib)
    def test_simple_download(self):
        elasticurl_download_args = [elasticurl_path, '-v', 'TRACE', '-o', 'elastigirl.png', 'https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png']
        run_command(elasticurl_download_args)

        urllib.request.urlretrieve('https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png', 'elastigirl_expected.png')

        if not filecmp.cmp('elastigirl.png', 'elastigirl_expected.png', shallow=False):
            raise RuntimeError('downloaded files do not match')

if __name__ == '__main__':
    unittest.main()