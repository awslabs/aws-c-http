# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.

import sys
import os.path
import subprocess

TIMEOUT = 300

canary_args = sys.argv[1:]
if not canary_args:
    print('You must pass the canary cmd prefix')
    sys.exit(-1)

program_to_run = canary_args[0]

if not os.path.exists(program_to_run):
    print(f'the {program_to_run} is not found, skip canary test')
    sys.exit(0)

# We don't have args to pass to canary yet. TODO add args for canary


def run_command(args):
    # gather all stderr and stdout to a single string that we print only if things go wrong
    process = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timedout = False
    try:
        output = process.communicate(timeout=TIMEOUT)[0]
    except subprocess.TimeoutExpired:
        timedout = True
        process.kill()
        output = process.communicate()[0]
    finally:
        if process.returncode != 0 or timedout:
            args_str = subprocess.list2cmdline(args)
            print(args_str)
            for line in output.splitlines():
                print(line.decode())
            if timedout:
                raise RuntimeError("Timeout happened after {secs} secs from: {cmd}".format(
                    secs=TIMEOUT, cmd=args_str))
            else:
                raise RuntimeError("Return code {code} from: {cmd}".format(
                    code=process.returncode, cmd=args_str))
        else:
            print(output.decode("utf-8"))


run_command(canary_args)
