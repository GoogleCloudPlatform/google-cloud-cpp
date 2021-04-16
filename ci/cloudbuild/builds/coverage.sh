#!/bin/bash
#
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

source "$(dirname "$0")/../../lib/init.sh"
source module ci/cloudbuild/builds/lib/bazel.sh
source module ci/cloudbuild/builds/lib/integration.sh

export CC=gcc
export CXX=g++

mapfile -t args < <(bazel::common_args)
args+=("--instrumentation_filter=/google/cloud[/:],/generator[/:]")
args+=("--instrument_test_targets")
bazel coverage "${args[@]}" --test_tag_filters=-integration-test ...
mapfile -t integration_args < <(integration::args)
GOOGLE_CLOUD_CPP_SPANNER_SLOW_INTEGRATION_TESTS="instance"
integration::bazel_with_emulators coverage "${args[@]}" "${integration_args[@]}"

# Where does this token come from? For triggered ci/pr builds GCB will securely
# inject this into the environment. See the "secretEnv" setting in the
# cloudbuild.yaml file. The value is stored in Secret Manager. You can store
# your own token in your personal project's Secret Manager so that your
# personal builds have coverage data uploaded to your own account. See also
# https://cloud.google.com/build/docs/securing-builds/use-secrets
if [[ -z "${CODECOV_TOKEN:-}" ]]; then
  io::log_h2 "No codecov token. Skipping upload."
  exit 0
fi

# Merges the coverage.dat files, which reduces the overall size by about 90%.
readonly MERGED_COVERAGE="/var/tmp/merged-coverage.lcov"
io::log_h2 "Merging coverage data into ${MERGED_COVERAGE}"
TIMEFORMAT="==> 🕑 merging done in %R seconds"
time {
  mapfile -t coverage_dat < <(find "$(bazel info output_path)" -name "coverage.dat")
  io::log "Found ${#coverage_dat[@]} coverage.dat files"
  mapfile -t lcov_flags < <(printf -- "--add-tracefile=%s\n" "${coverage_dat[@]}")
  lcov --quiet "${lcov_flags[@]}" --output-file "${MERGED_COVERAGE}"
  ls -lh "${MERGED_COVERAGE}"
}

codecov_args=(
  "-X" "gcov"
  "-f" "${MERGED_COVERAGE}"
  "-q" "${HOME}/coverage-report.txt"
  "-B" "${BRANCH_NAME}"
  "-C" "${COMMIT_SHA}"
  "-P" "${PR_NUMBER:-}"
  "-b" "${BUILD_ID:-}"
)
io::log_h2 "Uploading ${MERGED_COVERAGE} to codecov.io"
io::log "Flags: ${codecov_args[*]}"
TIMEFORMAT="==> 🕑 codecov.io upload done in %R seconds"
time {
  env -i CODECOV_TOKEN="${CODECOV_TOKEN:-}" HOME="${HOME}" \
    bash <(curl -s https://codecov.io/bash) "${codecov_args[@]}"
}
