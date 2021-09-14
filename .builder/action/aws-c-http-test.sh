PROXY_SETUP=/tmp/setup_proxy_test_env.sh
if [ -f "$PROXY_SETUP" ]; then
    source $PROXY_SETUP
    echo "setting proxy integration test envrionment"
fi

cd ./build/aws-c-http/
ctest --output-on-failure
