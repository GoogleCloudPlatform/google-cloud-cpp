# Copyright 2017 Google Inc.
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

# Configure the cctz dependency, this can be found as a submodule, package, or
# installed with pkg-config support.
set(GOOGLE_CLOUD_CPP_CCTZ_PROVIDER "module"
        CACHE STRING "How to find the Abseil library")
set_property(CACHE GOOGLE_CLOUD_CPP_CCTZ_PROVIDER
        PROPERTY STRINGS "module" "package" "pkg-config")

if ("${GOOGLE_CLOUD_CPP_CCTZ_PROVIDER}" STREQUAL "module")
    if (NOT "${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}" STREQUAL "module")
        message(ERROR "Both Abseil and cctz must be submodules or both must"
                " be installed libraries.  Currently Abseil is configured as "
                ${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}
                " and cctz as " ${GOOGLE_CLOUD_CPP_CCTZ_PROVIDER}
                ". Consider installing cctz too.")
    endif ()
    if (NOT CCTZ_ROOT_DIR)
        set(CCTZ_ROOT_DIR ${PROJECT_SOURCE_DIR}/third_party/cctz)
    endif ()
    if (NOT EXISTS "${CCTZ_ROOT_DIR}/CMakeLists.txt")
        message(ERROR "expected a CMakeLists.txt in CCTZ_ROOT_DIR")
    endif ()
    # cctz will include the `CTest` module and always compile the cctz tests, we
    # want to disable that.  The only way is to include the module first, disable
    # the tests, and then include the cctz CMakeLists.txt files.
    include(CTest)
    set(BUILD_TESTING OFF)
    add_subdirectory(${CCTZ_ROOT_DIR} third_party/cctz EXCLUDE_FROM_ALL)
elseif ("${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}" STREQUAL "package")
    if ("${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}" STREQUAL "module")
        message(ERROR "Both Abseil and cctz must be submodules or both must"
                " be installed libraries.  Currently Abseil is configured as "
                ${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}
                " and cctz as " ${GOOGLE_CLOUD_CPP_CCTZ_PROVIDER}
                ". Consider installing Abseil too.")
    endif ()
    find_package(cctz REQUIRED)
elseif ("${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}" STREQUAL "pkg-config")
    if ("${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}" STREQUAL "module")
        message(ERROR "Both Abseil and cctz must be submodules or both must"
                " be installed libraries.  Currently Abseil is configured as "
                ${GOOGLE_CLOUD_CPP_ABSEIL_PROVIDER}
                " and cctz as " ${GOOGLE_CLOUD_CPP_CCTZ_PROVIDER}
                ". Consider installing Abseil too.")
    endif ()
    # Find cctz using pkg-config
    include(FindPkgConfig)
    pkg_check_modules(cctz REQUIRED cctz)
    add_library(cctz INTERFACE IMPORTED)
    set_property(TARGET cctz PROPERTY INTERFACE_LINK_LIBRARIES
            PkgConfig::cctz)
endif ()
