#!/usr/bin/env bash
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

set -eu

if [[ -z "$(which cov-build)" ]]; then
  echo "This script requires the coverity scan tool (cov-build) in PATH"
  echo "Please download the tool, make sure your PATH includes the directory"
  echo "that contains it and try again."
  echo "More details on: https://scan.coverity.com/download"
  exit 1
fi

# Coverity scan is pre-configured to run with gcc, so do the same here.
export CXX=g++
export CC=gcc

# Running with coverity-scan and ccache seems like a bad idea, disable ccache.
# Also build in Debug mode because this is too slow in Release mode.
cmake -H. -B.coverity \
    -DCMAKE_BUILD_TYPE=Debug \
    -DGOOGLE_CLOUD_CPP_ENABLE_CCACHE=OFF

# The project dependencies should be built without coverity-scan, any errors in
# them are not actionable.
cmake --build .coverity --target grpc_project -- -j $(nproc)
cmake --build .coverity --target curl_project -- -j $(nproc)
cmake --build .coverity --target crc32c_project -- -j $(nproc)
cmake --build .coverity --target googletest_project -- -j $(nproc)

# The proto-generated files contain too many errors, and they are not
# actionable, so they are built without coverity-scan too.
cmake --build .coverity --target skip-scanbuild-targets -- -j $(nproc)

# Run coverity scan over our code.
cov-build --dir cov-int cmake --build .coverity -- -j $(nproc)
