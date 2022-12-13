import Builder
import sys
import os
import re


class AWSCHttpTest(Builder.Action):

    def _export_env_var(self, filename, env):
        with open(filename) as file:
            pattern = re.compile("(\w+) (\w+)=(.+)")
            for i in file.readlines():
                match = pattern.match(i)
                if match != None:
                    env.shell.setenv(match.groups()[1], match.groups()[2])
                    print(match.groups()[1])

    def run(self, env):
        actions = []
        if os.path.exists('/tmp/setup_proxy_test_env.sh'):
            # For proxy integration test, we download the setup script to tmp/ from codebuild/linux-integration-tests.yml
            # aws s3 cp s3://aws-crt-test-stuff/setup_proxy_test_env.sh /tmp/setup_proxy_test_env.sh
            print("setting proxy integration test environment")
            self._export_env_var('/tmp/setup_proxy_test_env.sh', env)
            env.shell.setenv('AWS_PROXY_NO_VERIFY_PEER', 'on')
        if os.path.exists('./build/aws-c-http/'):
            # This is the directory (relative to repo root) that will contain the build when the repo is built directly by the
            # builder
            os.chdir('./build/aws-c-http/')
        elif os.path.exists('../../aws-c-http'):
            # This is the directory (relative to repo root) that will contain the build when the repo is built as an upstream
            # consumer
            os.chdir('../../aws-c-http')

        actions.append(['ctest', '--output-on-failure'])
        # generate the test coverage report whenever possible, will be ignored by ctest if there is no test coverage data available.
        actions.append(['ctest', '-T', 'coverage'])

        return Builder.Script(actions, name='aws-c-http-test')
