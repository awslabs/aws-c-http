echo ON
mkdir install
cd install
set INSTALL_DIR=%cd%
cd ..
mkdir aws-c-common-build
mkdir aws-c-compression-build
mkdir aws-c-io-build
mkdir aws-c-http-build
cd aws-c-common-build
cmake -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%" -DBUILD_TESTING=OFF ..\aws-c-common || goto error
cmake --build .\ --target install --config RelWithDebInfo || goto error
cd ..
cd aws-c-compression-build
cmake -DCMAKE_PREFIX_PATH="%INSTALL_DIR%" -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%" -DBUILD_TESTING=OFF ..\aws-c-compression || goto error
cmake --build .\ --target install --config RelWithDebInfo || goto error
cd ..
cd aws-c-io-build
cmake -DCMAKE_PREFIX_PATH="%INSTALL_DIR%" -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%" -DBUILD_TESTING=OFF ..\aws-c-io || goto error
cmake --build .\ --target install --config RelWithDebInfo || goto error
cd ..
cd aws-c-http-build
cmake -DCMAKE_PREFIX_PATH="%INSTALL_DIR%" -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%" -DBUILD_TESTING=OFF ..\aws-c-http || goto error
cmake --build .\ --target install --config RelWithDebInfo || goto error
cd ..

"%INSTALL_DIR%\bin\elasticurl.exe" --version || goto error
"%INSTALL_DIR%\bin\elasticurl.exe" -v TRACE https://example.com || goto error

goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%

