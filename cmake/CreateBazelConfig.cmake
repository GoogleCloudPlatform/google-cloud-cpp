# ~~~
# Copyright 2020 Google LLC
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

function (write_bazel_copyright FILENAME YEAR)
    file(WRITE "${FILENAME}" "# Copyright ${YEAR} Google LLC")
    file(
        APPEND "${FILENAME}"
        [=[

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
#
# DO NOT EDIT -- GENERATED BY CMake -- Change the CMakeLists.txt file if needed

]=])
endfunction ()

# Generate a Bazel configuration file with the headers and sources for a given
# target. The generated file can be loaded from a BUILD file to create the
# corresponding targets in Bazel.
function (create_bazel_config TARGET)
    cmake_parse_arguments(_CREATE_BAZEL_CONFIG_OPT "" "YEAR" "" ${ARGN})
    if ("${_CREATE_BAZEL_CONFIG_OPT_YEAR}" STREQUAL "")
        set(_CREATE_BAZEL_CONFIG_OPT_YEAR "2018")
    endif ()
    if (NOT TARGET ${TARGET})
        message(
            FATAL_ERROR "create_bazel_config requires a target name: ${TARGET}")
    endif ()
    set(filename "${TARGET}.bzl")
    set(H)
    set(CC)
    get_target_property(target_type ${TARGET} TYPE)
    if (${target_type} STREQUAL "INTERFACE_LIBRARY")
        get_target_property(sources ${TARGET} INTERFACE_SOURCES)
    else ()
        get_target_property(sources ${TARGET} SOURCES)
    endif ()
    foreach (src ${sources})
        # Some files need to be specificied with an absolute path (mainly
        # sources for INTERFACE libraries). Compute the relative path because
        # Bazel does not like absolute filenames.
        string(REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/" "" relative "${src}")
        string(FIND "${src}" "${CMAKE_CURRENT_BINARY_DIR}" in_binary_dir)
        if ("${in_binary_dir}" EQUAL 0)
            # Skip files in the binary directory, they are generated and handled
            # differently by our Bazel BUILD files.
        elseif ("${src}" MATCHES "\\.inc$")
            list(APPEND H ${relative})
        elseif ("${src}" MATCHES "\\.h$")
            list(APPEND H ${relative})
        elseif ("${src}" MATCHES "\\.cc$")
            list(APPEND CC ${relative})
        endif ()
    endforeach ()
    write_bazel_copyright(${filename} ${_CREATE_BAZEL_CONFIG_OPT_YEAR})
    file(APPEND "${filename}" [=[
"""Automatically generated source lists for ]=])
    file(APPEND "${filename}" ${TARGET})
    file(
        APPEND "${filename}"
        [=[ - DO NOT EDIT."""

]=])
    file(APPEND "${filename}" "${TARGET}_hdrs = [\n")
    foreach (src ${H})
        file(APPEND "${filename}" "    \"${src}\",\n")
    endforeach ()
    file(APPEND "${filename}" "]\n\n")
    file(APPEND "${filename}" "${TARGET}_srcs = [\n")
    foreach (src ${CC})
        file(APPEND "${filename}" "    \"${src}\",\n")
    endforeach ()
    file(APPEND "${filename}" "]\n")
endfunction ()

# Export a list to a .bzl file, mostly used to export names of unit tests.
function (export_list_to_bazel filename VAR)
    cmake_parse_arguments(_EXPORT_LIST_TO_BAZEL_OPT "" "YEAR" "" ${ARGN})
    if ("${_EXPORT_LIST_TO_BAZEL_OPT_YEAR}" STREQUAL "")
        set(_EXPORT_LIST_TO_BAZEL_OPT_YEAR "2018")
    endif ()
    write_bazel_copyright(${filename} ${_EXPORT_LIST_TO_BAZEL_OPT_YEAR})
    file(
        APPEND "${filename}"
        [=[
"""Automatically generated unit tests list - DO NOT EDIT."""

]=])
    file(APPEND "${filename}" "${VAR} = [\n")
    foreach (item ${${VAR}})
        file(APPEND "${filename}" "    \"${item}\",\n")
    endforeach ()
    file(APPEND "${filename}" "]\n")
endfunction ()

# Export a number of variables to a .bzl file, mostly used to export version
# information.
function (export_variables_to_bazel filename)
    cmake_parse_arguments(_EXPORT_VARIABLES_TO_BAZEL_OPT "" "YEAR" "" ${ARGN})
    if ("${_EXPORT_VARIABLES_TO_BAZEL_OPT_YEAR}" STREQUAL "")
        set(_EXPORT_VARIABLES_TO_BAZEL_OPT_YEAR "2019")
    endif ()
    write_bazel_copyright(${filename} ${_EXPORT_VARIABLES_TO_BAZEL_OPT_YEAR})
    file(
        APPEND "${filename}"
        [=[
"""Automatically generated version numbers - DO NOT EDIT."""

]=])
    foreach (item ${_EXPORT_VARIABLES_TO_BAZEL_OPT_UNPARSED_ARGUMENTS})
        file(APPEND "${filename}" "${item} = \"${${item}}\"\n")
    endforeach ()
endfunction ()
