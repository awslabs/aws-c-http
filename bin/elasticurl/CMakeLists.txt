project(elasticurl C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

file(GLOB ELASTICURL_SRC
        "*.c"
        )

set(ELASTICURL_PROJECT_NAME elasticurl)
add_executable(${ELASTICURL_PROJECT_NAME} ${ELASTICURL_SRC})
set_target_properties(${ELASTICURL_PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)

set(CMAKE_C_FLAGS_DEBUGOPT "")

#set warnings
if (MSVC)
    target_compile_options(${ELASTICURL_PROJECT_NAME} PRIVATE /W4 /WX)
else ()
    target_compile_options(${ELASTICURL_PROJECT_NAME} PRIVATE -Wall -Wno-long-long -pedantic -Werror)
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "" OR CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(${ELASTICURL_PROJECT_NAME} PRIVATE "-DDEBUG_BUILD")
endif ()

target_include_directories(${ELASTICURL_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${ELASTICURL_PROJECT_NAME} aws-c-http)
