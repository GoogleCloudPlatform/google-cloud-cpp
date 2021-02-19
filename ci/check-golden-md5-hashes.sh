#!/usr/bin/env bash
# Copyright 2021 Google LLC
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

source "$(dirname "$0")/lib/init.sh"
source module lib/io.sh

if [[ "${CHECK_GENERATED_CODE_HASH}" != "yes" ]]; then
  echo "Skipping the generated code hash check as it is disabled for this build."
  exit 0
fi

cd "${PROJECT_ROOT}"
num_current_files=$(find generator/integration_tests/golden -name '*.gcpcxx.*' | wc -l)
num_hashed_files=$(cat "${PROJECT_ROOT}"/ci/etc/generator-golden-md5-hashes.md5 | wc -l)

if [ "${num_current_files}" -gt "${num_hashed_files}" ]; then
  io::log_red "New golden files have been added."
  io::log_yellow "Run 'ci/kokoro/docker/build.sh generate-libraries' to update."
  exit 1
fi

hash_check_result=$(md5sum --check --quiet "${PROJECT_ROOT}/ci/etc/generator-golden-md5-hashes.sh") || true

if [[ ${hash_check_result} != "" ]]; then
  io::log_yellow "Run 'ci/kokoro/docker/build.sh generate-libraries' to update."
fi

exit 0
