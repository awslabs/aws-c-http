cmake_minimum_required(VERSION 3.1)
project(aws-c-http C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

include(AwsCFlags)
include(Sanitizers)
include(CheckCCompilerFlag)

option(BUILD_PORTABLE_BINARIES
        "Build Relocatable Binaries, this will turn off features that will fail on older kernels than used for the build."
        OFF)

file(GLOB AWS_HTTP_HEADERS
        "include/aws/http/*.h"
        )

file(GLOB AWS_HTTP_PRIV_HEADERS
        "include/aws/http/private/*.h"
        )

file(GLOB AWS_HTTP_TESTING_HEADERS
        "include/aws/testing/http/*.h"
        "include/aws/testing/http/*.inl"
        )

file(GLOB AWS_HTTP_SRC
        "source/*.c"
        )

file(GLOB HTTP_HEADERS
        ${AWS_HTTP_HEADERS}
        ${AWS_HTTP_PRIV_HEADERS}
        ${AWS_HTTP_TESTING_HEADERS}
        )

file(GLOB HTTP_SRC
        ${AWS_HTTP_SRC}
        )

add_library(${CMAKE_PROJECT_NAME} ${LIBTYPE} ${HTTP_HEADERS} ${HTTP_SRC})
aws_set_common_properties(${CMAKE_PROJECT_NAME})
aws_add_sanitizers(${CMAKE_PROJECT_NAME})

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

find_package(aws-c-common REQUIRED)
#find_package(aws-c-io REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC aws-c-common ${PLATFORM_LIBS})
#target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC aws-c-io ${PLATFORM_LIBS})

install(FILES ${AWS_HTTP_HEADERS} DESTINATION "include/aws/HTTP")
install(FILES ${AWS_HTTP_TESTING_HEADERS} DESTINATION "include/aws/testing/HTTP")

install(
        TARGETS ${CMAKE_PROJECT_NAME} EXPORT ${CMAKE_PROJECT_NAME}-config
        ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        COMPONENT library
)

export(TARGETS ${CMAKE_PROJECT_NAME} FILE ${CMAKE_PROJECT_NAME}-config.cmake)
install(EXPORT ${CMAKE_PROJECT_NAME}-config DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/${CMAKE_PROJECT_NAME}/cmake/")

include(CTest)
add_subdirectory(tests)
