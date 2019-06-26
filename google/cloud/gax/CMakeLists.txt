# ~~~
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ~~~

# This should be included from the top level CMakeLists file
set(GAX_CPP_VERSION_MAJOR 0)
set(GAX_CPP_VERSION_MINOR 1)
set(GAX_CPP_VERSION_PATCH 0)

set(DOXYGEN_PROJECT_NAME "Google Cloud C++ API Extensions")
set(DOXYGEN_PROJECT_BRIEF
    "API Extensions for the Google Cloud C++ Client Library")
set(
    DOXYGEN_PROJECT_NUMBER
    "${GAX_CPP_VERSION_MAJOR}.${GAX_CPP_VERSION_MINOR}.${GAX_CPP_VERSION_PATCH}"
    )
set(DOXYGEN_EXAMPLE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/examples)
set(DOXYGEN_PREDEFINED "GAX_CPP_NS=v${GAX_CPP_VERSION_MAJOR}")
set(DOXYGEN_EXCLUDE_PATTERNS
    "*/google/cloud/gax/README.md"
    "*/google/cloud/gax/ci/*"
    "*/google/cloud/gax/internal/*"
    "*/google/cloud/gax/testing/*"
    "*/google/cloud/gax/tests/*"
    "*/google/cloud/gax/*_test.cc")
set(DOXYGEN_EXCLUDE_SYMBOLS "internal")
set(DOXYGEN_TAGFILES "${PROJECT_BINARY_DIR}/google/cloud/cloud.tag=../common")
google_cloud_cpp_set_doxygen_tagfiles()

include(GoogleCloudCppCommon)
if (TARGET gax-docs AND TARGET cloud-docs)
    add_dependencies(gax-docs cloud-docs)
endif ()

# Define an interface library, i.e., a library that really has no sources, and
# add public target options to it.  The targets then use the library via
# target_link_libraries(target PRIVATE gax_common_options), which implicitly
# adds the options to those targets, but does *not* add the options to any
# targets that depend on them.  This is a CMake idiom to add options to targets
# without having to painfully set special variables, it also allows users to add
# more common options without having to touch the code.
add_library(gax_common_options INTERFACE)
google_cloud_cpp_add_common_options(gax_common_options)

# Enable unit tests
include(CTest)

# Generate the version information from the CMake values.
configure_file(version_info.h.in ${CMAKE_CURRENT_SOURCE_DIR}/version_info.h)

# Export the version information for Bazel.
include(CreateBazelConfig)

# the library
add_library(gax_cpp
            grpc_error_delegate.h
            grpc_error_delegate.cc
            version.h
            version.cc
            version_info.h)
target_link_libraries(gax_cpp
                      PUBLIC google_cloud_cpp_common gRPC::grpc++ gRPC::grpc
                      PRIVATE gax_common_options)
target_include_directories(gax_cpp
                           PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
                                  $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
                                  $<INSTALL_INTERFACE:include>)
target_compile_options(gax_cpp PUBLIC ${GOOGLE_CLOUD_CPP_EXCEPTIONS_FLAG})
set_target_properties(
    gax_cpp
    PROPERTIES
        VERSION
        ${GAX_CPP_VERSION_MAJOR}.${GAX_CPP_VERSION_MINOR}.${GAX_CPP_VERSION_PATCH}
        SOVERSION
        ${GAX_CPP_VERSION_MAJOR})
add_library(googleapis-c++::gax ALIAS gax_cpp)

include(CreateBazelConfig)
create_bazel_config(gax_cpp YEAR 2019)
google_cloud_cpp_add_clang_tidy(gax_cpp)

if (BUILD_TESTING)
    # TODO: add gax_cpp_testing if necessary.

    # List the unit tests, then setup the targets and dependencies.
    set(gax_cpp_unit_tests grpc_error_delegate_test.cc)

    # Export the list of unit tests so the Bazel BUILD file can pick it up.
    export_list_to_bazel("gax_cpp_unit_tests.bzl"
                         "gax_cpp_unit_tests"
                         YEAR
                         2019)

    foreach (fname ${gax_cpp_unit_tests})
        string(REPLACE "/"
                       "_"
                       target
                       ${fname})
        string(REPLACE ".cc"
                       ""
                       target
                       ${target})
        add_executable(${target} ${fname})
        target_link_libraries(${target}
                              PRIVATE gax_cpp
                                      google_cloud_cpp_testing
                                      google_cloud_cpp_common
                                      GTest::gmock_main
                                      GTest::gmock
                                      GTest::gtest
                                      gRPC::grpc++
                                      gRPC::grpc
                                      gax_common_options)
        if (MSVC)
            target_compile_options(${target} PRIVATE "/bigobj")
        endif ()
        add_test(NAME ${target} COMMAND ${target})
    endforeach ()
endif ()

option(GOOGLE_CLOUD_CPP_FORCE_STATIC_ANALYZER_ERRORS
       "If set, enable tests that force errors detected by the static analyzer."
       "")
mark_as_advanced(GOOGLE_CLOUD_CPP_FORCE_STATIC_ANALYZER_ERRORS)
if (GOOGLE_CLOUD_CPP_FORCE_STATIC_ANALYZER_ERRORS)
    target_compile_definitions(gax_cpp_force_sanitizer_failures_test PRIVATE
                               -DGAX_CPP_FORCE_STATIC_ANALYZER_ERRORS)
endif ()

# TODO: add_subdirectory(tests) if necessary.

if ("${GOOGLE_CLOUD_CPP_GRPC_PROVIDER}" STREQUAL "external")
    set(GOOGLE_CLOUD_CPP_GAX_ENABLE_INSTALL "OFF")
    message(
        WARNING
            "The install target has been disabled for the gax_cpp"
            " library because one of the dependencies is set to use external"
            " projects. When building against external projects the resulting"
            " libraries are not installable. The necessary dependencies may"
            " not installed in your system, or the versions installed in your"
            " system may not match the version used to compile the"
            " google-cloud-cpp libraries. "
            ""
            "Please consult the README.md file for details on how to compile "
            "against pre-installed versions of the google-cloud-cpp "
            "dependencies.
GPRC     PROVIDER = ${GOOGLE_CLOUD_CPP_GRPC_PROVIDER}
PROTOBUF PROVIDER = ${GOOGLE_CLOUD_CPP_PROTOBUF_PROVIDER}")
else()
    set(GOOGLE_CLOUD_CPP_GAX_ENABLE_INSTALL "ON")
endif ()

if ("${GOOGLE_CLOUD_CPP_GAX_ENABLE_INSTALL}")
    # Install the libraries and headers in the locations determined by
    # GNUInstallDirs
    install(TARGETS gax_common_options
            EXPORT gax-targets
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

    # Export the CMake targets to make it easy to create configuration files.
    install(EXPORT gax-targets
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/gax_cpp")

    install(TARGETS gax_cpp
            EXPORT gax-targets
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
    google_cloud_cpp_install_headers(gax_cpp include/google/cloud/gax)

    # Setup global variables used in the following *.in files.
    set(GOOGLE_CLOUD_CPP_CONFIG_VERSION_MAJOR ${GAX_CPP_VERSION_MAJOR})
    set(GOOGLE_CLOUD_CPP_CONFIG_VERSION_MINOR ${GAX_CPP_VERSION_MINOR})
    set(GOOGLE_CLOUD_CPP_CONFIG_VERSION_PATCH ${GAX_CPP_VERSION_PATCH})
    set(GOOGLE_CLOUD_CPP_PC_NAME
        "Google API Extensions for the Google Cloud C++ Client Library")
    set(
        GOOGLE_CLOUD_CPP_PC_DESCRIPTION
        "Provides Google API extensions for the Google Cloud C++ Client Library."
        )
    set(GOOGLE_CLOUD_CPP_PC_REQUIRES "google_cloud_cpp_common")
    set(GOOGLE_CLOUD_CPP_PC_LIBS "-lgax_cpp")

    # Create and install the pkg-config files.
    configure_file("${PROJECT_SOURCE_DIR}/google/cloud/config.pc.in"
                   "gax_cpp.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/gax_cpp.pc" DESTINATION
                  "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

    # Create and install the CMake configuration files.
    configure_file("config.cmake.in" "gax_cpp-config.cmake" @ONLY)
    configure_file("${PROJECT_SOURCE_DIR}/google/cloud/config-version.cmake.in"
                   "gax_cpp-config-version.cmake" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/gax_cpp-config.cmake"
                  "${CMAKE_CURRENT_BINARY_DIR}/gax_cpp-config-version.cmake"
                  DESTINATION
                  "${CMAKE_INSTALL_LIBDIR}/cmake/gax_cpp")
endif ()
