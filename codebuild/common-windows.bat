echo "Installing python version: %* via choco"
choco install python3 -y
call RefreshEnv.cmd

set CMAKE_ARGS=%*

set BUILDS_DIR=%TEMP%\builds
set INSTALL_DIR=%BUILDS_DIR%\install
mkdir %BUILDS_DIR%
mkdir %INSTALL_DIR%

CALL :install_library aws-c-common
CALL :install_library aws-c-io
CALL :install_library aws-c-compression

mkdir %BUILDS_DIR%\aws-c-http-build
cd %BUILDS_DIR%\aws-c-http-build
cmake %CMAKE_ARGS% -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%" -DCMAKE_PREFIX_PATH="%INSTALL_DIR%" %CODEBUILD_SRC_DIR% || goto error
cmake --build . --config RelWithDebInfo || goto error
ctest -V || goto error
python %CODEBUILD_SRC_DIR%\integration-testing\http_client_test.py bin\elasticurl\RelWithDebInfo\elasticurl.exe || goto error

goto :EOF

:install_library
mkdir %BUILDS_DIR%\%~1-build
cd %BUILDS_DIR%\%~1-build
git clone https://github.com/awslabs/%~1.git
cmake %CMAKE_ARGS% -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%" -DCMAKE_PREFIX_PATH="%INSTALL_DIR%" %~1 || goto error
cmake --build . --target install --config RelWithDebInfo || goto error
exit /b %errorlevel%

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
