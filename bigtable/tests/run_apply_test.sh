#!/usr/bin/env bash
#
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

set -eu

function kill_emulator {
    kill ${EMULATOR_PID}
    wait >/dev/null 2>&1
}

echo "Launching Cloud Bigtable emulator in the background"
"${GOPATH}/bin/emulator" >emulator.log 2>&1 </dev/null &
EMULATOR_PID=$!
if [ $? -ne 0 ]; then
    echo "emulator failed, aborting"
    cat emulator.log
    exit 1
fi

trap kill_emulator EXIT

export BIGTABLE_EMULATOR_HOST=localhost:9000
# Avoid repetition
readonly CBT_ARGS="-project emulated -instance emulated -creds default"
# Wait until the emulator starts responding.
delay=1
connected=no
readonly ATTEMPTS=$(seq 1 8)
for attempt in $ATTEMPTS; do
    if "${GOPATH}/bin/cbt" $CBT_ARGS ls >/dev/null 2>&1; then
        connected=yes
        break
    fi
    sleep $delay
    delay=$((delay * 2))
done

if [ "${connected}" = "no" ]; then
    echo "Cannot connect to emulator, aborting."
    exit 1
else
    echo "Successfully connected to the emulator."
fi

echo "Creating test-table in the emulator"
"${GOPATH}/bin/cbt" $CBT_ARGS createtable test-table
echo "Creating family in test-table"
"${GOPATH}/bin/cbt" $CBT_ARGS createfamily test-table fam

# Run the integration tests
echo
echo "Running Table::Apply() integration test"
./apply_test

kill_emulator
trap - EXIT
