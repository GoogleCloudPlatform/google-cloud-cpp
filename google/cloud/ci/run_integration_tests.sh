#!/usr/bin/env bash
#
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

# This script should is called from the build directory, and it finds other
# scripts in the source directory using its own path.
if [ -z "${PROJECT_ROOT+x}" ]; then
  readonly PROJECT_ROOT="$(cd "$(dirname $0)/../../.."; pwd)"
fi
source "${PROJECT_ROOT}/ci/colors.sh"

# If the build has excluded the examples, then skip them.
if [ -d google/cloud/examples ]; then
  (cd google/cloud/examples ; \
   "${PROJECT_ROOT}"/google/cloud/examples/run_gcs2cbt_emulator.sh)
else
  echo "${COLOR_YELLOW}[ SKIPPED  ]${COLOR_RESET} google/cloud examples" \
    " as the examples are not compiled for this build"
fi
