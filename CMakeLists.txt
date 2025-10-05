cmake_minimum_required(VERSION 3.15)
project(unxorer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(IDASDK_ROOT "${CMAKE_CURRENT_LIST_DIR}/ida-sdk/src" CACHE PATH "Root of the IDA SDK")

if(NOT EXISTS "${IDASDK_ROOT}/include/ida.hpp")
    message(FATAL_ERROR "'${IDASDK_ROOT}' does not look like an IDA SDK (missing include/ida.hpp). Did you forget to init git submodules?")
endif()

message(STATUS "Using IDA SDK at: ${IDASDK_ROOT}")

string(TIMESTAMP BUILD_DATE "%Y-%m-%d %H:%M:%S")
find_package(Git QUIET)
if(Git_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short=8 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
    set(GIT_HASH "nogit")
endif()

message(STATUS "Build date: ${BUILD_DATE}, Git hash: ${GIT_HASH}")

find_package(fmt CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn)

add_library(unxorer SHARED "src/plugin.cpp" "src/emulator.cpp" "src/console.cpp" "src/results.cpp" "src/handler.cpp")
target_link_libraries(unxorer PRIVATE fmt::fmt PkgConfig::UNICORN)

target_include_directories(unxorer PRIVATE "${IDASDK_ROOT}/include")
target_compile_definitions(unxorer PRIVATE __IDP__ __PLUGIN__ __EA64__
    BUILD_DATE=\"${BUILD_DATE}\"
    GIT_HASH=\"${GIT_HASH}\"
)

if(WIN32)
    if(EXISTS "${IDASDK_ROOT}/lib/x64_win_vc_64")
        set(IDA_LIB_DIR "${IDASDK_ROOT}/lib/x64_win_vc_64")
    else()
        set(IDA_LIB_DIR "${IDASDK_ROOT}/lib/x64_win_vc_64_home")
    endif()
    
    target_link_libraries(unxorer PRIVATE "${IDA_LIB_DIR}/ida.lib")
    set_target_properties(unxorer PROPERTIES SUFFIX ".dll")
else()
    if(EXISTS "${IDASDK_ROOT}/lib/x64_linux_gcc_64")
        set(IDA_LIB_DIR "${IDASDK_ROOT}/lib/x64_linux_gcc_64")
    else()
        set(IDA_LIB_DIR "${IDASDK_ROOT}/lib/x64_linux_gcc_64_home")
    endif()

    find_library(IDAAPI idaapi PATHS "${IDA_LIB_DIR}" NO_DEFAULT_PATH)
    target_link_libraries(unxorer PRIVATE "${IDAAPI}")
    set_target_properties(unxorer PROPERTIES SUFFIX ".so")
endif()

set_target_properties(unxorer PROPERTIES PREFIX "")

set_target_properties(unxorer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins")
