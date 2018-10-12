# !/usr/bin/env powershell

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

# Stop on errors. This is similar to `set -e` on Unix shells.
$ErrorActionPreference = "Stop"

# First check the required environment variables.
if (-not (Test-Path env:PROVIDER)) {
    throw "Aborting build because the PROVIDER environment variable is not set."
}
if (-not (Test-Path env:GENERATOR)) {
    throw "Aborting build because the GENERATOR environment variable is not set."
}
if (-not (Test-Path env:CONFIG)) {
    throw "Aborting build because the CONFIG environment variable is not set."
}

$CONFIG = $env:CONFIG
$GENERATOR = $env:GENERATOR
$PROVIDER = $env:PROVIDER

git submodule update --init
if ($LastExitCode) {
    throw "git submodule failed with exit code $LastExitCode"
}

# By default assume "module", use the configuration parameters and build in the `build-output` directory.
$cmake_flags=@("-G$GENERATOR", "-DCMAKE_BUILD_TYPE=$CONFIG", "-H.", "-Bbuild-output")

# This script expects vcpkg to be installed in ..\vcpkg, discover the full
# path to that directory:
$dir = Split-Path (Get-Item -Path ".\" -Verbose).FullName

# Run the vcpkg integration.
$integrate = "$dir\vcpkg\vcpkg.exe integrate install"
Invoke-Expression $integrate
if ($LastExitCode) {
    throw "vcpkg integrate failed with exit code $LastExitCode"
}

# Setup the environment for vcpkg:
$cmake_flags += "-DGOOGLE_CLOUD_CPP_GRPC_PROVIDER=$PROVIDER"
$cmake_flags += "-DGOOGLE_CLOUD_CPP_GMOCK_PROVIDER=$PROVIDER"
$cmake_flags += "-DCMAKE_TOOLCHAIN_FILE=`"$dir\vcpkg\scripts\buildsystems\vcpkg.cmake`""
$cmake_flags += "-DVCPKG_TARGET_TRIPLET=x64-windows-static"

# Configure CMake and create the build directory.
cmake $cmake_flags
if ($LastExitCode) {
    throw "cmake config failed with exit code $LastExitCode"
}

Get-Date -Format o
cmake --build build-output --config $CONFIG -- /m
if ($LastExitCode) {
    throw "cmake for 'all' target failed with exit code $LastExitCode"
}

Get-Date -Format o
cd build-output
ctest --output-on-failure -C $CONFIG -j 4
if ($LastExitCode) {
    throw "ctest failed with exit code $LastExitCode"
}
