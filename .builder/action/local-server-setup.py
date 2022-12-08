"""
Setup local server for tests
"""

import Builder

import os
import sys
import subprocess
import atexit


class LocalServerSetup(Builder.Action):
    """
    Set up this machine for running the local h2 server test.
    To run the local server related test, use `-cmake-extra=-DENABLE_LOCALHOST_INTEGRATION_TESTS=ON` from builder.
    Not running local server tests for every CI as it takes a while.

    This action should be run in the 'pre_build_steps' or 'build_steps' stage.
    """

    def run(self, env):
        self.env = env
        python_path = sys.executable
        # install dependency for mock server
        self.env.shell.exec(python_path,
                            '-m', 'pip', 'install', 'h2', check=True)
        # check the deps can be import correctly
        self.env.shell.exec(python_path,
                            '-c', 'import h2', check=True)

        base_dir = os.path.dirname(os.path.realpath(__file__))
        dir = os.path.join(base_dir, "..", "..", "tests", "py_localhost")
        os.chdir(dir)

        p_server = subprocess.Popen([python_path, "server.py"])
        p_non_tls_server = subprocess.Popen([python_path, "non_tls_server.py"])

        @atexit.register
        def close_local_server():
            p_server.terminate()
            p_non_tls_server.terminate()
