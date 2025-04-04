project(h2benchmark C)

file(GLOB CANARY_SRC
        "*.c"
        )

set(PROJECT_NAME h2benchmark)
add_executable(${PROJECT_NAME} ${CANARY_SRC})
aws_set_common_properties(${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME} aws-c-http)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " h2benchmark will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime)
