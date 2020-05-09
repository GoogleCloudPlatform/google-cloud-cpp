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

if [[ $# -lt 1 ]]; then
  echo "Usage: $(basename "$0") <binary-dir> [ctest-args]"
  exit 1
fi

BINARY_DIR="$(
  cd "${1}"
  pwd
)"
readonly BINARY_DIR
shift
ctest_args=("$@")

CMDDIR="$(dirname "$0")"
readonly CMDDIR
PROJECT_ROOT="$(
  cd "${CMDDIR}/../../../.."
  pwd
)"
readonly PROJECT_ROOT

SPANNER_EMULATOR_PID=0
if [[ -z "${CLOUD_SDK_LOCATION:-}" ]]; then
  echo 1>&2 "You must set CLOUD_SDK_LOCATION to find the emulator"
  exit 1
fi

# We cannot use `gcloud beta emulators spanner start` because there is no way
# to kill the emulator at the end using that command.
readonly SPANNER_EMULATOR_CMD="${CLOUD_SDK_LOCATION}/bin/cloud_spanner_emulator/emulator_main"
if [[ ! -x "${SPANNER_EMULATOR_CMD}" ]]; then
  echo 1>&2 "The spanner emulator does not seem to be installed, aborting"
  exit 1
fi

function kill_emulator() {
  echo -n "Killing Spanner Emulator [${SPANNER_EMULATOR_PID}] "
  kill "${SPANNER_EMULATOR_PID}" || echo -n "-"
  wait "${SPANNER_EMULATOR_PID}" >/dev/null 2>&1 || echo -n "+"
  echo -n "."
  echo " done."
}

################################################
# Wait until the port number is printed in the log file for one of the
# emulators
# Globals:
#   None
# Arguments:
#   logfile: the name of the logfile to wait on.
# Returns:
#   None
################################################
wait_for_port() {
  local -r logfile="$1"
  shift

  local emulator_port="0"
  local -r expected=' : Server address: '
  for attempt in $(seq 1 8); do
    if grep -q "${expected}" "${logfile}"; then
      # The port number is whatever is after the last ':'. Note that on IPv6
      # there may be multiple ':' characters, and recall that regular
      # expressions are greedy. If grep has multiple matches this breaks,
      # which is Okay because then the emulator is exhibiting unexpected
      # behavior.
      emulator_port=$(grep "${expected}" "${logfile}" | sed 's/^.*://')
      break
    fi
    sleep 1
  done

  if [[ "${emulator_port}" = "0" ]]; then
    echo "Cannot determine Cloud Spanner emulator port." >&2
    kill_emulator
    exit 1
  fi

  echo "${emulator_port}"
}

function start_emulator() {
  echo "Launching Cloud Spanner emulator in the background"
  trap kill_emulator EXIT

  # The tests typically run in a Docker container, where the ports are largely
  # free; when using in manual tests, you can set EMULATOR_PORT.
  "${SPANNER_EMULATOR_CMD}" --host_port localhost:0 >emulator.log 2>&1 </dev/null &
  SPANNER_EMULATOR_PID=$!
  local -r emulator_port="$(wait_for_port emulator.log)"
  export SPANNER_EMULATOR_HOST="localhost:${emulator_port}"
}

# Use the same configuration parameters as we use for testing against
# production. Easier to maintain just one copy.
source "${PROJECT_ROOT}/ci/etc/integration-tests-config.sh"
export GOOGLE_CLOUD_CPP_AUTO_RUN_EXAMPLES=yes

cd "${BINARY_DIR}"
start_emulator

ctest -L "spanner-integration-tests" "${ctest_args[@]}"
exit_status=$?

kill_emulator
trap '' EXIT

exit "${exit_status}"
