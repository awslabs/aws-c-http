project(h2benchmark C)

file(GLOB H2BENCHMARK_SRC
        "*.c"
        )

set(PROJECT_NAME h2benchmark)
add_executable(${PROJECT_NAME} ${H2BENCHMARK_SRC})
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

# Option-parsing tests. These all finish inside s_parse_options() before any network
# setup, so they need no server. --help exits 0; every rejected value exits 1.
if (BUILD_TESTING)
    add_test(NAME h2benchmark_help COMMAND ${PROJECT_NAME} --help)
    set_tests_properties(h2benchmark_help PROPERTIES PASS_REGULAR_EXPRESSION "usage: h2benchmark")

    # 0 is documented as a valid log level ("none") and is the default, so it must be accepted.
    add_test(NAME h2benchmark_log_level_zero COMMAND ${PROJECT_NAME} --log-level 0 --help)
    set_tests_properties(h2benchmark_log_level_zero PROPERTIES PASS_REGULAR_EXPRESSION "usage: h2benchmark")

    foreach(case
            "rate_secs_text;--rate-secs;notanumber"
            "rate_secs_zero;--rate-secs;0"
            "max_connections_negative;--max-connections;-1"
            "streams_trailing_garbage;--streams-per-connection;12abc"
            "rate_threshold_text;--rate-threshold;xyz"
            "log_level_out_of_range;--log-level;99"
            "unknown_option;--no-such-option")
        list(POP_FRONT case case_name)
        add_test(NAME h2benchmark_reject_${case_name} COMMAND ${PROJECT_NAME} ${case})
        set_tests_properties(h2benchmark_reject_${case_name} PROPERTIES WILL_FAIL TRUE)
    endforeach()
endif()
