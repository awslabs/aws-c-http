
import Builder
import sys
import os
import re


class AWSCHttpTest(Builder.Action):

    def _export_env_var(filename, env):
        file = open(filename)
        pattern = re.compile("(\w+) (\w+)=(.+)")
        for i in file.readlines():
            match = pattern.match(i)
            if match != None:
                env.shell.setenv(match.groups()[1], match.groups()[2])
                print(match.groups()[1])

    def run(self, env):
        actions = []
        if os.path.exists('/tmp/setup_proxy_test_env.sh'):
            print("setting proxy integration test environment")
            self._export_env_var('/tmp/setup_proxy_test_env.sh', env)
            env.shell.setenv('AWS_PROXY_NO_VERIFY_PEER', 'on')
        if os.path.exists('./build/aws-c-http/'):
            os.chdir('./build/aws-c-http/')
        elif os.path.exists('../../aws-c-http'):
            os.chdir('../../aws-c-http')

        localhost = False
        if os.path.exists('/tmp/setup_localhost_test.bat'):
            print("setting localhost integration test environment")
            self._export_env_var('/tmp/setup_localhost_test.bat', env)
            localhost = True

        if os.path.exists('/tmp/nginx-1.21.6.tar.gz') or localhost:
            actions.append(['ctest', '--output-on-failure',
                           '-R', 'localhost_integ_*'])
        else:
            actions.append(['ctest', '--output-on-failure'])
        return Builder.Script(actions, name='aws-c-http-test')
