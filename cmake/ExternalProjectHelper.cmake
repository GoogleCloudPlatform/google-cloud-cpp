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

include(GNUInstallDirs)

function (set_library_properties_for_external_project _target _lib)
    cmake_parse_arguments(F_OPT "ALWAYS_SHARED" "" "" ${ARGN})
    # This is the main disadvantage of external projects. The typicaly flow with
    # CMake is:
    # ~~~
    # 1. Configure: cmake discovers where your libraries and dependencies are,
    #    and it generates Makefiles (or Ninja files or VisualStudio files) to
    #    compile the code. The paths and/or flags needed for the dependencies
    #    are embedded in the generated files.
    # 2. Compile: make, Ninja or VisualStudio compile your code.
    # ~~~
    #
    # With external projects the flow is the same, except that step 2 has
    # additional sub-steps:
    #
    # ~~~
    # 1. Configure: as above. But the external projects are not "discovered".
    # 2. Compile: make, Ninja, or Visual Studio compile your code. But new
    #    steps are introduced to the compilation:
    # 2.1: Download any external projects that your code depends on.
    # 2.2: Compile (and maybe test) those external projects.
    # 2.3: Install those external projects in the ${CMAKE_BINARY_DIR}/...
    # 2.4: Compile your code.
    # ~~~
    #
    # We cannot use an external project's cmake configuration file because they
    # are not created nor installed until after the project is compiled.
    # However, these files would be needed in step 1 if we want to use them in
    # CMake.
    #
    # The alternative is to manually create "IMPORTED" libraries with the right
    # paths. Generally this is possible because we control how the external
    # projects are compiled and installed.
    if (WIN32)
        set(
            _libfullname
            "${CMAKE_STATIC_LIBRARY_PREFIX}${_lib}${CMAKE_LIB}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            )
    elseif("${BUILD_SHARED_LIBS}" OR "${F_OPT_ALWAYS_SHARED}")
        set(
            _libfullname
            "${CMAKE_SHARED_LIBRARY_PREFIX}${_lib}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            )
    else()
        set(
            _libfullname
            "${CMAKE_STATIC_LIBRARY_PREFIX}${_lib}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            )
    endif ()

    # Some libraries always install themselves in the "lib/" directory, while
    # others use "lib64/" if the distributions uses that directory. We just have
    # to "know" how to handle these libraries, if the library was already
    # installed then we could use FindPackage() and the *-config.cmake file
    # would have the right information. But the configuration for external
    # libraries runs before the installation of the external libraries, so we
    # cannot use FindPackage(). Sigh.
    set(_libs_always_install_in_libdir "grpc++" "grpc" "gpr" "cares" "z")

    if (${_lib} IN_LIST _libs_always_install_in_libdir)
        set(_libpath "${PROJECT_BINARY_DIR}/external/lib/${_libfullname}")
    else()
        set(
            _libpath
            "${PROJECT_BINARY_DIR}/external/${CMAKE_INSTALL_LIBDIR}/${_libfullname}"
            )
    endif ()
    set(_includepath "${PROJECT_BINARY_DIR}/external/include")
    message(STATUS "Configuring ${_target} with ${_libpath}")
    set_property(TARGET ${_target}
                 APPEND
                 PROPERTY INTERFACE_LINK_LIBRARIES "${_libpath}")
    # Manually create the directory, it will be created as part of the build,
    # but this runs in the configuration phase, and CMake generates an error if
    # we add an include directory that does not exist yet.
    file(MAKE_DIRECTORY "${_includepath}")
    set_property(TARGET ${_target}
                 APPEND
                 PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${_includepath}")
endfunction ()

function (set_executable_name_for_external_project VAR _exe)
    set(${VAR}
        "${PROJECT_BINARY_DIR}/external/bin/${_exe}${CMAKE_EXECUTABLE_SUFFIX}"
        PARENT_SCOPE)
endfunction ()
