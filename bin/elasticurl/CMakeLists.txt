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
