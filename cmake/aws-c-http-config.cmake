include(CMakeFindDependencyMacro)

find_dependency(aws-c-io)
find_dependency(aws-c-compression)

include(${CMAKE_CURRENT_LIST_DIR}/@CMAKE_PROJECT_NAME@-targets.cmake)
