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
FixProtobufTargets
------------------

Old versions (pre CMake-3.9) of the FindProtobuf module do not define the
`protobuf::*` targets.  This module defines these targets in a portable way.

- This module always defines the ``protobuf::*`` target, while the stock
  CMake module only defines them after CMake-3.9.

The following variables can be set and are optional:

``protobuf_DEBUG``
  Show debug messages.
``protobuf_USE_STATIC_LIBS``
  Set to ON to force the use of the static libraries.
  Default is OFF.

Defines the following variables:

``protobuf_FOUND``
  Found the protobuf library
``protobuf_VERSION``
  Version of package found.

The following :prop_tgt:`IMPORTED` targets are also defined:

``protobuf::libprotobuf``
  The protobuf library.
``protobuf::libprotobuf-lite``
  The protobuf lite library.
``protobuf::libprotoc``
  The protoc library.
``protobuf::protoc``
  The protoc compiler.

Example:

.. code-block:: cmake

  find_package(Protobuf REQUIRED)
  add_executable(bar bar.cc)
  target_link_libraries(bar PRIVATE protobuf::libprotobuf)

#]=======================================================================]

if (protobuf_DEBUG)
    # Output some of their choices
    message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "protobuf_USE_STATIC_LIBS = ${protobuf_USE_STATIC_LIBS}")
endif ()

# Always load thread support, even on Windows.
find_package(Threads REQUIRED)

# First try to use the ``protobufConfig.cmake`` or ``protobuf-config.cmake``
# file if it was installed. This is common on systems (or package managers)
# where protobuf was compiled and installed with `CMake`.
find_package(protobuf NO_MODULE QUIET)

if (protobuf_DEBUG)
    # Output the progress so far.
    message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "protobuf_FOUND = ${protobuf_FOUND}")
endif ()

if (NOT protobuf_FOUND)
    find_package(Protobuf QUIET)

    if (Protobuf_FOUND)
        set(protobuf_FOUND 1)
        set(protobuf_VERSION ${Protobuf_VERSION})

        # Old versions of the FindProtobuf module do not define targets.
        # We define them here to make the rest of the code simpler.
        if (NOT TARGET protobuf::libprotobuf)
            add_library(protobuf::libprotobuf INTERFACE IMPORTED)
            set_property(TARGET protobuf::libprotobuf
                PROPERTY IMPORTED_LOCATION ${Protobuf_LIBRARY})
            set_property(TARGET protobuf::libprotobuf
                PROPERTY INTEFACE_INCLUDE_DIRECTORIES ${Protobuf_INCLUDE_DIR})
            set_property(TARGET protobuf::libprotobuf
                APPEND
                PROPERTY INTERFACE_LINK_LIBRARIES Threads::Threads)
        endif ()

        if (NOT TARGET protobuf::libprotobuf-lite)
            add_library(protobuf::libprotobuf-lite INTERFACE IMPORTED)
            set_property(TARGET protobuf::libprotobuf-lite
                PROPERTY IMPORTED_LOCATION ${Protobuf_LITE_LIBRARY})
            set_property(TARGET protobuf::libprotobuf-lite
                PROPERTY INTEFACE_INCLUDE_DIRECTORIES ${Protobuf_INCLUDE_DIR})
            set_property(TARGET protobuf::libprotobuf-lite
                APPEND
                PROPERTY INTERFACE_LINK_LIBRARIES Threads::Threads)
        endif ()
    endif ()
endif ()

if (protobuf_DEBUG)
    # Output the progress so far.
    message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "protobuf_FOUND = ${protobuf_FOUND}")
endif ()

find_package(PkgConfig QUIET)
if ((NOT protobuf_FOUND) AND PkgConfig_FOUND)
    # Could not protobuf using a *Config.cmake file, try using `pkg-config`.
    include(PkgConfigHelper)

    pkg_check_modules(Protobuf REQUIRED protobuf)
    add_library(protobuf::libprotobuf INTERFACE IMPORTED)
    set_library_properties_from_pkg_config(protobuf::libprotobuf Protobuf)
    set_property(TARGET protobuf::libprotobuf
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES Threads::Threads)
 
    pkg_check_modules(Protobuf_LITE REQUIRED protobuf-lite)
    add_library(protobuf::libprotobuf INTERFACE IMPORTED)
    set_library_properties_from_pkg_config(protobuf::libprotobuf-lite Protobuf_LITE)
    set_property(TARGET protobuf::libprotobuf-lite
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES Threads::Threads)

    if (protobuf_DEBUG)
        message(
            STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "protobuf_FOUND = ${protobuf_FOUND}")
        message(
            STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                   "protobuf_VERSION = ${protobuf_VERSION}")
    endif ()
endif ()


# We also should try to find the protobuf C++ plugin for the protocol buffers
# compiler. Without it, it is not possible to generate the protobuf bindings.
if (protobuf_FOUND)
    # The target may already exist, do not create it again if it does.
    if (NOT TARGET protobuf::protoc)
        # Discover the protoc compiler location.
        find_program(
            _protobuf_PROTOC_EXECUTABLE
            NAMES protoc
            DOC "The Google Protocol Buffers Compiler")
        add_executable(protobuf::protoc IMPORTED)        
        set_property(TARGET protobuf::protoc
                     PROPERTY IMPORTED_LOCATION ${PROTOBUF_PROTOC_EXECUTABLE})
        unset(_protobuf_PROTOC_EXECUTABLE)
    endif ()

    if (protobuf_DEBUG)
        get_target_property(_protobuf_PROTOC_EXECUTABLE protobuf::protoc
                            IMPORTED_LOCATION)
        message(STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                    "LOCATION=${_protobuf_PROTOC_EXECUTABLE}")
    endif ()
endif ()

if (protobuf_DEBUG)
    message(
        STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                "protobuf_FOUND = ${protobuf_FOUND}")
    message(
        STATUS "[ ${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE} ] "
                "protobuf_VERSION = ${protobuf_VERSION}")
endif ()
