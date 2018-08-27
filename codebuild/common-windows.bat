
mkdir build
cd build
cmake %* -DPERFORM_HEADER_CHECK=ON -DCMAKE_BUILD_TYPE="Release" ../ || goto error
msbuild.exe aws-c-http.vcxproj /p:Configuration=Release || goto error
msbuild.exe tests/aws-c-http-assert-tests.vcxproj /p:Configuration=Release
msbuild.exe tests/aws-c-http-tests.vcxproj /p:Configuration=Release
ctest -V || goto error

goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
