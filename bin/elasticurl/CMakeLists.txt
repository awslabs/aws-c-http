project(elasticurl C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

file(GLOB ELASTICURL_SRC
        "*.c"
        )

set(ELASTICURL_PROJECT_NAME elasticurl)
add_executable(${ELASTICURL_PROJECT_NAME} ${ELASTICURL_SRC})
aws_set_common_properties(${ELASTICURL_PROJECT_NAME})


target_include_directories(${ELASTICURL_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${ELASTICURL_PROJECT_NAME} aws-c-http)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " elasticurl will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${ELASTICURL_PROJECT_NAME}
        EXPORT ${ELASTICURL_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)
