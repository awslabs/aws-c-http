
import Builder
import sys
import os


class AWSCHttpTest(Builder.Action):

    def run(self, env):
        actions = []
        if os.path.exists('/tmp/setup_proxy_test_env.sh'):
            print("setting proxy integration test environment")
            actions.append('.', '/tmp/setup_proxy_test_env.sh')
            env.shell.setenv('AWS_PROXY_NO_VERIFY_PEER', 'on')
        if os.path.exists('./build/aws-c-http/'):
            os.chdir('./build/aws-c-http/')
        elif os.path.exists('../../aws-c-http'):
            os.chdir('../../aws-c-http')

        localhost = False
        if os.path.exists('/tmp/setup_localhost_test.bat'):
            print("setting localhost integration test environment")
            actions.append(['.', '/tmp/setup_localhost_test.bat'])
            localhost = True

        if os.path.exists('/tmp/nginx-1.21.6.tar.gz') or localhost:
            actions.append(['ctest', '--output-on-failure',
                           '-R', 'localhost_integ_*'])
        else:
            actions.append(['ctest', '--output-on-failure'])
        return Builder.Script(actions, name='aws-c-http-test')
