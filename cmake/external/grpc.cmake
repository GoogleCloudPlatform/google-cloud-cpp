# ~~~
# Copyright 2018 Google LLC
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

include(ExternalProjectHelper)
include(external/c-ares)
include(external/ssl)
include(external/protobuf)

if (NOT TARGET gprc_project)
    # Give application developers a hook to configure the version and hash
    # downloaded from GitHub.
    set(GOOGLE_CLOUD_CPP_GRPC_URL
        "https://github.com/grpc/grpc/archive/v1.17.0.tar.gz")
    set(GOOGLE_CLOUD_CPP_GRPC_SHA256
        "d98d41399783c8f9f0cd8d8fec3920c8378d3a77ec4b7bdf228832cac4ab8617")

    if ("${CMAKE_GENERATOR}" STREQUAL "Unix Makefiles"
        OR "${CMAKE_GENERATOR}" STREQUAL "Ninja")
        include(ProcessorCount)
        processorcount(NCPU)
        set(PARALLEL "--" "-j" "${NCPU}")
    else()
        set(PARALLEL "")
    endif ()

    create_external_project_library_byproduct_list(grpc_byproducts
                                                   "grpc"
                                                   "grpc++"
                                                   "gpr"
                                                   "address_sorting")

    include(ExternalProject)
    externalproject_add(
        grpc_project
        DEPENDS c_ares_project protobuf_project ssl_project
        EXCLUDE_FROM_ALL ON
        PREFIX "external/grpc"
        INSTALL_DIR "external"
        URL ${GOOGLE_CLOUD_CPP_GRPC_URL}
        URL_HASH SHA256=${GOOGLE_CLOUD_CPP_GRPC_SHA256}
        CMAKE_ARGS ${GOOGLE_CLOUD_CPP_EXTERNAL_PROJECT_CCACHE}
                   -DCMAKE_BUILD_TYPE=Release
                   -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
                   -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                   -DgRPC_BUILD_TESTS=OFF
                   -DgRPC_ZLIB_PROVIDER=package
                   -DgRPC_SSL_PROVIDER=package
                   -DgRPC_CARES_PROVIDER=package
                   -DgRPC_PROTOBUF_PROVIDER=package
        BUILD_COMMAND ${CMAKE_COMMAND}
                      --build
                      <BINARY_DIR>
                      ${PARALLEL}
        BUILD_BYPRODUCTS
            ${grpc_byproducts}
            <INSTALL_DIR>/bin/grpc_cpp_plugin${CMAKE_EXECUTABLE_SUFFIX}
        LOG_DOWNLOAD ON
        LOG_CONFIGURE ON
        LOG_BUILD ON
        LOG_INSTALL ON)

    add_library(gRPC::address_sorting INTERFACE IMPORTED)
    set_library_properties_for_external_project(gRPC::address_sorting
                                                address_sorting)
    add_dependencies(gRPC::address_sorting grpc_project)

    add_library(gRPC::gpr INTERFACE IMPORTED)
    set_library_properties_for_external_project(gRPC::gpr gpr)
    add_dependencies(gRPC::gpr grpc_project)
    set_property(TARGET gRPC::gpr
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES c-ares::cares)

    add_library(gRPC::grpc INTERFACE IMPORTED)
    set_library_properties_for_external_project(gRPC::grpc grpc)
    add_dependencies(gRPC::grpc grpc_project)
    set_property(TARGET gRPC::grpc
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES
                          gRPC::address_sorting
                          gRPC::gpr
                          OpenSSL::SSL
                          OpenSSL::Crypto
                          protobuf::libprotobuf)

    add_library(gRPC::grpc++ INTERFACE IMPORTED)
    set_library_properties_for_external_project(gRPC::grpc++ grpc++)
    add_dependencies(gRPC::grpc++ grpc_project)
    set_property(TARGET gRPC::grpc++
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES gRPC::grpc c-ares::cares)

    # Discover the protobuf compiler and the gRPC plugin.
    add_executable(protoc IMPORTED)
    add_dependencies(protoc protobuf_project)
    set_executable_name_for_external_project(protoc protoc)

    add_executable(grpc_cpp_plugin IMPORTED)
    add_dependencies(grpc_cpp_plugin grpc_project)
    set_executable_name_for_external_project(grpc_cpp_plugin grpc_cpp_plugin)

    list(APPEND PROTOBUF_IMPORT_DIRS "${PROJECT_BINARY_DIR}/external/include")
endif ()
