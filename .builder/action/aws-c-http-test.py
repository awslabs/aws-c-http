
import Builder
import sys
import os


class AWSCHttpTest(Builder.Action):

    def run(self, env):
        if os.path.exists('/tmp/setup_proxy_test_env.sh'):
            env.shell.setenv('AWS_PROXY_NO_VERIFY_PEER', 'on')
            print("setting proxy integration test environment")
        if os.path.exists('./build/aws-c-http/'):
            os.chdir('./build/aws-c-http/')
        elif os.path.exists('../../aws-c-http'):
            os.chdir('../../aws-c-http')

        actions = []
        if os.path.exists('/tmp/nginx-1.21.6.tar.gz') or os.environ.get('AWS_TEST_LOCALHOST_HOST')!=None:
            actions.append(['ctest', '--output-on-failure', '-R', 'localhost_integ_*'])
        else:
            actions.append(['ctest', '--output-on-failure'])

        return Builder.Script(actions, name='aws-c-http-test')
