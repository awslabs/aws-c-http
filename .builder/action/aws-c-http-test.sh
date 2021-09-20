PROXY_SETUP=/tmp/setup_proxy_test_env.sh
if [ -f "$PROXY_SETUP" ]; then
    source $PROXY_SETUP
    export AWS_PROXY_NO_VERIFY_PEER=on
    echo "setting proxy integration test envrionment"
fi

cd ./build/aws-c-http/
ctest --output-on-failure
