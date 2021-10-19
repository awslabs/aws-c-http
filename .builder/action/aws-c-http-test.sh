PROXY_SETUP=/tmp/setup_proxy_test_env.sh
if [ -f "$PROXY_SETUP" ]; then
    source $PROXY_SETUP
    export AWS_PROXY_NO_VERIFY_PEER=on
    echo "setting proxy integration test environment"
fi

if [ -d "./build/aws-c-http/" ]; then
    # This is the directory (relative to repo root) that will contain the build when the repo is built directly by the
    # builder
    cd ./build/aws-c-http/
elif [ -d "../../aws-c-http" ]; then
    # This is the directory (relative to repo root) that will contain the build when the repo is built as an upstream
    # consumer
    cd ../../aws-c-http
fi

ctest --output-on-failure

