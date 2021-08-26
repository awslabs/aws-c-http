import os

if os.path.exists("/tmp/setup_proxy_test_env.sh"):
    print("Setting up proxy environment")
    os.system("source /tmp/setup_proxy_test_env.sh")
