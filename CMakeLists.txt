cmake_minimum_required(VERSION 3.9...3.31)
# In-source builds inherit aws-c-common's module path from the parent. Standalone
# builds must locate the installed modules here: find_package needs an enabled
# language, so it cannot run until after project().
if (NOT IN_SOURCE_BUILD)
    find_file(AWS_GET_VERSION_MODULE AwsGetVersion.cmake
            PATH_SUFFIXES lib/cmake/aws-c-common/modules lib64/cmake/aws-c-common/modules)
    if (NOT AWS_GET_VERSION_MODULE)
        message(FATAL_ERROR "Could not find AwsGetVersion.cmake from an installed aws-c-common. Set CMAKE_PREFIX_PATH to the aws-c-common install prefix.")
    endif()
    get_filename_component(AWS_COMMON_MODULE_DIR "${AWS_GET_VERSION_MODULE}" DIRECTORY)
    list(APPEND CMAKE_MODULE_PATH "${AWS_COMMON_MODULE_DIR}")
endif()

include(AwsGetVersion)
aws_get_version(AWS_C_HTTP_VERSION AWS_C_HTTP_SOVERSION)

project(aws-c-http LANGUAGES C VERSION ${AWS_C_HTTP_VERSION})
option(ENABLE_PROXY_INTEGRATION_TESTS "Whether to run the proxy integration tests that rely on pre-configured proxy" OFF)
option(ENABLE_LOCALHOST_INTEGRATION_TESTS "Whether to run the integration tests that rely on pre-configured localhost" OFF)

if (NOT IN_SOURCE_BUILD)
    # this is required so we can use aws-c-common's CMake modules
    find_package(aws-c-common REQUIRED)
endif()

include(AwsCFlags)
include(AwsCheckHeaders)
include(AwsSharedLibSetup)
include(AwsSanitizers)
include(CheckCCompilerFlag)
include(AwsFindPackage)
include(GNUInstallDirs)

file(GLOB AWS_HTTP_HEADERS
        "include/aws/http/*.h"
        )

file(GLOB AWS_HTTP_PRIV_HEADERS
        "include/aws/http/private/*.h"
        )

file(GLOB AWS_HTTP_SRC
        "source/*.c"
        )

file(GLOB HTTP_HEADERS
        ${AWS_HTTP_HEADERS}
        ${AWS_HTTP_PRIV_HEADERS}
        )

file(GLOB HTTP_SRC
        ${AWS_HTTP_SRC}
        )

add_library(${PROJECT_NAME} ${HTTP_HEADERS} ${HTTP_SRC})
aws_set_common_properties(${PROJECT_NAME})
aws_prepare_symbol_visibility_args(${PROJECT_NAME} "AWS_HTTP")
aws_add_sanitizers(${PROJECT_NAME})

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${AWS_C_HTTP_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${AWS_C_HTTP_SOVERSION})

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

aws_use_package(aws-c-io)
aws_use_package(aws-c-compression)
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS})

aws_prepare_shared_lib_exports(${PROJECT_NAME})

aws_check_headers(${PROJECT_NAME} ${AWS_HTTP_HEADERS})
install(FILES ${AWS_HTTP_HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/aws/http")

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/${TARGET_DIR}/"
        NAMESPACE AWS::
        COMPONENT Development)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/"
        COMPONENT Development)

include(CTest)
if (NOT BYO_CRYPTO AND BUILD_TESTING)
    add_subdirectory(tests)
    if (NOT CMAKE_CROSSCOMPILING)
        add_subdirectory(bin/elasticurl)
        add_subdirectory(bin/h2benchmark)
    endif()
endif()
