#!/usr/bin/env bash
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

set -eu

if [[ $# -ne 1 ]]; then
  echo "Usage: $(basename "$0") <project-root>"
  exit 1
fi

readonly PROJECT_ROOT="$1"

source "${PROJECT_ROOT}/ci/colors.sh"
source "${PROJECT_ROOT}/ci/etc/integration-tests-config.sh"
source "${PROJECT_ROOT}/ci/etc/quickstart-config.sh"

echo
echo "================================================================"
log_yellow "update or install Bazel."

# macOS does not have sha256sum by default, but `shasum -a 256` does the same
# thing:
function sha256sum() { shasum -a 256 "$@"; }
export -f sha256sum

mkdir -p "cmake-out/download"
(
  cd "cmake-out/download"
  "${PROJECT_ROOT}/ci/install-bazel.sh" >/dev/null
)

echo
echo "================================================================"
readonly BAZEL_BIN="$HOME/bin/bazel"
log_normal "Using Bazel in ${BAZEL_BIN}"
"${BAZEL_BIN}" version
"${BAZEL_BIN}" shutdown

bazel_args=(
  # On macOS gRPC does not compile correctly unless one defines this:
  "--copt=-DGRPC_BAZEL_BUILD"
  # We need this environment variable because on macOS gRPC crashes if it
  # cannot find the credentials, even if you do not use them. Some of the
  # unit tests do exactly that.
  "--test_output=errors"
  "--verbose_failures=true"
  "--keep_going")

run_quickstart="false"
readonly CONFIG_DIR="${KOKORO_GFILE_DIR:-/private/var/tmp}"
readonly CREDENTIALS_FILE="${CONFIG_DIR}/kokoro-run-key.json"
readonly ROOTS_PEM_SOURCE="https://raw.githubusercontent.com/grpc/grpc/master/etc/roots.pem"
if [[ -r "${CREDENTIALS_FILE}" ]]; then
  if [[ -r "${CONFIG_DIR}/roots.pem" ]]; then
    run_quickstart="true"
  elif wget -O "${CONFIG_DIR}/roots.pem" -q "${ROOTS_PEM_SOURCE}"; then
    run_quickstart="true"
  fi
fi
readonly run_quickstart

echo "================================================================"
cd "${PROJECT_ROOT}"

build_quickstart() {
  local -r library="$1"

  cd "${PROJECT_ROOT}/google/cloud/${library}/quickstart"
  log_normal "capture bazel version"
  ${BAZEL_BIN} version
  for repeat in 1 2 3; do
    echo
    log_yellow "Fetching deps for ${library}'s quickstart [${repeat}/3]."
    if "${BAZEL_BIN}" fetch -- ...; then
      break
    else
      log_yellow "bazel fetch failed with $?"
    fi
  done

  echo
  log_yellow "Compiling ${library}'s quickstart"
  "${BAZEL_BIN}" build "${bazel_args[@]}" ...

  if [[ "${run_quickstart}" == "true" ]]; then
    echo
    log_yellow "Running ${library}'s quickstart."
    args=()
    while IFS="" read -r line; do
      args+=("${line}")
    done < <(quickstart_arguments "${library}")
    env "GOOGLE_APPLICATION_CREDENTIALS=${CREDENTIALS_FILE}" \
      "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=${CONFIG_DIR}/roots.pem" \
      "${BAZEL_BIN}" run "${bazel_args[@]}" "--spawn_strategy=local" \
      :quickstart -- "${args[@]}"
  fi
}

errors=""
for library in $(quickstart_libraries); do
  echo
  echo "================================================================"
  log_yellow "Building ${library}'s quickstart"
  if ! build_quickstart "${library}"; then
    log_red "Building ${library}'s quickstart failed"
    errors="${errors} ${library}"
  else
    log_green "Building ${library}'s quickstart was successful"
  fi
done

echo "================================================================"
if [[ -z "${errors}" ]]; then
  log_green "All quickstart builds were successful"
else
  log_red "Build failed for ${errors}"
  exit 1
fi

exit 0
