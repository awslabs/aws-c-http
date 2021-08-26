FILE=/tmp/setup_proxy_test_env.sh
if [ -f "$FILE" ]; then
    source $FILE
    echo "setting proxy integration test envrionment"
fi
