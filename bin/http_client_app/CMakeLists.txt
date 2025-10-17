project(http_client_c_socks5_app C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_PREFIX_PATH}/lib/cmake")

file(GLOB HTTP_CLIENT_APP_SRC
        "*.c"
        )

set(HTTP_CLIENT_APP_PROJECT_NAME http_client_app)
add_executable(${HTTP_CLIENT_APP_PROJECT_NAME} ${HTTP_CLIENT_APP_SRC})
aws_set_common_properties(${HTTP_CLIENT_APP_PROJECT_NAME})

target_include_directories(${HTTP_CLIENT_APP_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${HTTP_CLIENT_APP_PROJECT_NAME} PRIVATE aws-c-http)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " http client app will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${HTTP_CLIENT_APP_PROJECT_NAME}
        EXPORT ${HTTP_CLIENT_APP_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)