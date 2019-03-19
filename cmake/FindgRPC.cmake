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

#[=======================================================================[.rst:
FindgRPC
--------

Locate and configure the gRPC library.

The following variables can be set and are optional:

``gRPC_DEBUG``
  Show debug messages.
``gRPC_USE_STATIC_LIBS``
  Set to ON to force the use of the static libraries.
  Default is OFF.

Defines the following variables:

``gRPC_FOUND``
  Found the gRPC library
``gRPC_VERSION``
  Version of package found.

The following :prop_tgt:`IMPORTED` targets are also defined:

``gRPC::grpc++``
  The gRPC C++ library.
``gRPC::grpc``
  The gRPC C core library.
``gRPC::cpp_plugin``
  The C++ plugin for the Protobuf protoc compiler.

The following cache variables are also available to set or use:

Example:

.. code-block:: cmake

  find_package(gRPC REQUIRED)
  add_executable(bar bar.cc)
  target_link_libraries(bar PRIVATE gRPC::grpc++)

#]=======================================================================]

if (gRPC_DEBUG)
    # Output some of their choices
    message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "gRPC_USE_STATIC_LIBS = ${gRPC_USE_STATIC_LIBS}")
endif ()

# gRPC always requires Protobuf and thread support.
find_package(Threads REQUIRED)
find_package(ProtobufTargets REQUIRED)

# First try to use the `GrpcConfig.cmake` or `Grpc-config.cmake` file if it was
# installed. This is common on systems (or package managers) where gRPC was
# compiled and installed with `CMake`.
find_package(gRPC NO_MODULE QUIET)

if (gRPC_DEBUG)
    # Output some of their choices
    message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "gRPC_FOUND = ${gRPC_FOUND}")
endif ()

if (NOT gRPC_FOUND)
    # Could not gRPC using a *Config.cmake file, try using `pkg-config`.
    find_package(PkgConfig REQUIRED)
    include(PkgConfigHelper)

    # Find the core gRPC C library using pkg-config. If this is not found we
    # basically abort.
    pkg_check_modules(gRPC_c REQUIRED grpc)
    add_library(gRPC::grpc INTERFACE IMPORTED)
    set_library_properties_from_pkg_config(gRPC::grpc gRPC_c)
    set_property(TARGET gRPC::grpc
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES protobuf::libprotobuf)

    # Try to find the gRPC C++ library using pkg-config. We do this one last
    # because we want the values of gRPC_FOUND and gRPC_VERSION used here.
    pkg_check_modules(gRPC REQUIRED grpc++>=1.16)
    add_library(gRPC::grpc++ INTERFACE IMPORTED)
    set_library_properties_from_pkg_config(gRPC::grpc++ gRPC)
    set_property(TARGET gRPC::grpc++
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES gRPC::grpc)

    if (gRPC_DEBUG)
        message(
            STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "gRPC_FOUND = ${gRPC_FOUND}")
        message(
            STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "gRPC_VERSION = ${gRPC_VERSION}")
    endif ()
endif ()

# We also should try to find the gRPC C++ plugin for the protocol buffers
# compiler. Without it, it is not possible to generate the gRPC bindings.
if (gRPC_FOUND)
    # The target may already exist, do not create it again if it does.
    if (NOT TARGET gRPC::grpc_cpp_plugin)
        add_executable(gRPC::grpc_cpp_plugin IMPORTED)
    endif ()
    get_target_property(_gRPC_CPP_PLUGIN_EXECUTABLE gRPC::grpc_cpp_plugin
                        IMPORTED_LOCATION)
    message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "LOCATION=${_gRPC_CPP_PLUGIN_EXECUTABLE}")
    # Even if the target exists, gRPC CMake support files do not define the
    # executable for the imported target (at least they do not in v1.19.1), so
    # we need to define it ourselves.
    if (NOT _gRPC_CPP_PLUGIN_EXECUTABLE)
        find_program(_gRPC_CPP_PLUGIN_EXECUTABLE
                     NAMES grpc_cpp_plugin
                     DOC "The gRPC C++ plugin for protoc")
        if (_gRPC_CPP_PLUGIN_EXECUTABLE)
            mark_as_advanced(_gRPC_CPP_PLUGIN_EXECUTABLE)
            set_property(TARGET gRPC::grpc_cpp_plugin
                         PROPERTY IMPORTED_LOCATION
                                  ${_gRPC_CPP_PLUGIN_EXECUTABLE})
        else()
            set(gRPC_FOUND "grpc_cpp_plugin-NOTFOUND")
        endif ()
    endif ()
    message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "LOCATION=${_gRPC_CPP_PLUGIN_EXECUTABLE}")
endif ()
