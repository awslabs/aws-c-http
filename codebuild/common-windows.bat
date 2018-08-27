cd ../
set CMAKE_ARGS=%*

mkdir install

CALL :install_library aws-c-common

cd aws-c-io
mkdir build
cd build
cmake %CMAKE_ARGS% -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX=../../install ../ || goto error
cmake --build . --config Release || goto error
ctest -V

goto :EOF

:install_library
git clone https://github.com/awslabs/%~1.git
cd %~1
mkdir build
cd build
cmake %CMAKE_ARGS% -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX=../../install ../ || goto error
cmake --build . --target install --config Release || goto error
cd ../..
exit /b %errorlevel%

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
