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

if [[ -z "${PROJECT_ROOT+x}" ]]; then
  readonly PROJECT_ROOT="$(cd "$(dirname "$0")/../../../.."; pwd)"
fi
source "${PROJECT_ROOT}/ci/define-example-runner.sh"

function cleanup_instance {
  local project=$1
  local instance=$2
  shift 2

  echo
  echo "Cleaning up test instance projects/${project}/instances/${instance}"
  ./bigtable_instance_admin_snippets delete-instance "${project}" "${instance}"
}

function exit_handler {
  local project=$1
  local instance=$2
  shift 2

  if [[ -n "${BIGTABLE_INSTANCE_ADMIN_EMULATOR_HOST:-}" ]]; then
    kill_emulators
  else
    cleanup_instance "${project}" "${instance}"
  fi
}

# Run all the instance admin async examples.
#
# This function allows us to keep a single place where all the examples are
# listed. We want to run these examples in the continuous integration builds
# because they rot otherwise.
function run_all_instance_admin_async_examples {
  local project_id=$1
  local zone_id=$2
  local replication_zone_id=$3
  shift 2

  EMULATOR_LOG="instance-admin-emulator.log"

  # Create a (very likely unique) instance name.
  local -r INSTANCE="in-${RANDOM}-${RANDOM}"

  run_example ./instance_admin_async_snippets async-create-instance \
      "${project_id}" "${INSTANCE}" "${zone_id}"
  run_example ./instance_admin_async_snippets async-update-instance \
      "${project_id}" "${INSTANCE}"
  run_example ./instance_admin_async_snippets async-get-instance \
      "${project_id}" "${INSTANCE}"
  run_example ./instance_admin_async_snippets async-list-instances \
      "${project_id}"
  run_example ./instance_admin_async_snippets async-list-clusters \
      "${project_id}" "${INSTANCE}"
  run_example ./instance_admin_async_snippets async-list-all-clusters \
      "${project_id}"
  run_example ./instance_admin_async_snippets async-list-app-profiles \
      "${project_id}" "${INSTANCE}"
  run_example ./instance_admin_async_snippets async-create-cluster \
      "${project_id}" "${INSTANCE}" "${INSTANCE}-c2" "${replication_zone_id}"
  run_example ./instance_admin_async_snippets async-update-cluster \
      "${project_id}" "${INSTANCE}" "${INSTANCE}-c2"
  run_example ./instance_admin_async_snippets async-get-cluster \
      "${project_id}" "${INSTANCE}" "${INSTANCE}-c2"
  run_example ./instance_admin_async_snippets async-delete-cluster \
      "${project_id}" "${INSTANCE}" "${INSTANCE}-c2"
  run_example ./instance_admin_async_snippets async-create-app-profile \
      "${project_id}" "${INSTANCE}" "my-profile"
  run_example ./instance_admin_async_snippets async-get-app-profile \
      "${project_id}" "${INSTANCE}" "my-profile"
  run_example ./instance_admin_async_snippets async-update-app-profile \
      "${project_id}" "${INSTANCE}" "my-profile"
  run_example ./instance_admin_async_snippets async-delete-app-profile \
      "${project_id}" "${INSTANCE}" "my-profile"
  run_example ./instance_admin_async_snippets async-get-iam-policy \
      "${project_id}" "${INSTANCE}"
  run_example ./instance_admin_async_snippets async-set-iam-policy \
      "${project_id}" "${INSTANCE}" "roles/bigtable.user" \
      "serviceAccount:${SERVICE_ACCOUNT}"
  run_example ./instance_admin_async_snippets async-get-native-iam-policy \
      "${project_id}" "${INSTANCE}"
  run_example ./instance_admin_async_snippets async-set-native-iam-policy \
      "${project_id}" "${INSTANCE}" "roles/bigtable.user" \
      "serviceAccount:${SERVICE_ACCOUNT}"
  run_example ./instance_admin_async_snippets async-test-iam-permissions \
      "${project_id}" "${INSTANCE}" "bigtable.instances.delete"
  run_example ./instance_admin_async_snippets async-delete-instance \
      "${project_id}" "${INSTANCE}"

  # Verify that calling without a command produces the right exit status and
  # some kind of Usage message.
  run_example_usage ./instance_admin_async_snippets
}

# Run all the table admin async examples.
#
# This function allows us to keep a single place where all the examples are
# listed. We want to run these examples in the continuous integration builds
# because they rot otherwise.
function run_all_table_admin_async_examples {
  local project_id=$1
  local zone_id=$2
  shift 2

  EMULATOR_LOG="emulator.log"

  # Create a (very likely unique) instance name.
  local -r INSTANCE="in-${RANDOM}-${RANDOM}"

  # Use the same table in all the tests.
  local -r TABLE="sample-table-for-admin-${RANDOM}"

  # Use sample row key wherever needed.
  local -r ROW_KEY="sample-row-key-${RANDOM}"

  run_example ./bigtable_instance_admin_snippets create-instance \
      "${project_id}" "${INSTANCE}" "${zone_id}"

  run_example ./table_admin_async_snippets async-create-table \
      "${project_id}" "${INSTANCE}" "${TABLE}"
  run_example ./table_admin_async_snippets async-list-tables \
      "${project_id}" "${INSTANCE}"
  run_example ./table_admin_async_snippets async-get-table \
      "${project_id}" "${INSTANCE}" "${TABLE}"
  run_example ./table_admin_async_snippets async-modify-table \
      "${project_id}" "${INSTANCE}" "${TABLE}"
  run_example ./table_admin_async_snippets async-generate-consistency-token \
      "${project_id}" "${INSTANCE}" "${TABLE}"
  local token
  token="$(./table_admin_async_snippets async-generate-consistency-token \
      "${project_id}" "${INSTANCE}" "${TABLE}" | awk '{print $5}')"
  run_example ./table_admin_async_snippets async-check-consistency \
      "${project_id}" "${INSTANCE}" "${TABLE}" "${token}"
  run_example ./table_admin_async_snippets async-wait-for-consistency \
      "${project_id}" "${INSTANCE}" "${TABLE}" "${token}"
  run_example ./table_admin_async_snippets async-drop-rows-by-prefix \
      "${project_id}" "${INSTANCE}" "${TABLE}" "${ROW_KEY}"
  run_example ./table_admin_async_snippets async-drop-all-rows \
      "${project_id}" "${INSTANCE}" "${TABLE}"
  run_example ./table_admin_async_snippets async-delete-table \
      "${project_id}" "${INSTANCE}" "${TABLE}"

  run_example ./bigtable_instance_admin_snippets delete-instance \
      "${project_id}" "${INSTANCE}"

  # Verify that calling without a command produces the right exit status and
  # some kind of Usage message.
  run_example_usage ./table_admin_async_snippets
}

################################################
# Run the Bigtable examples for Async* operations on data.
# Globals:
#   None
# Arguments:
#   project_id: the Google Cloud Storage project used in the test. Can be a
#       fake project when testing against the emulator, as the emulator creates
#       projects on demand. It must be a valid, existing instance when testing
#       against production.
#   instance_id: the Google Cloud Bigtable instance used in the test. Can be a
#       fake instance when testing against the emulator, as the emulator creates
#       instances on demand. It must be a valid, existing instance when testing
#       against production.
# Returns:
#   None
################################################
function run_all_data_async_examples {
  local project_id=$1
  local instance_id=$2
  shift 2

  EMULATOR_LOG="instance-admin-emulator.log"

  # Use the same table in all the tests.
  local -r TABLE="data-ex-tbl-${RANDOM}-${RANDOM}"
  local -r APPLY_ROW_KEY="async-apply-row-${RANDOM}"
  local -r CHECK_AND_MUTATE_ROW_KEY="check-and-mutate-row-${RANDOM}"
  local -r READ_MODIFY_WRITE_ROW_KEY="read-modify-write-row-${RANDOM}"
  run_example ./table_admin_snippets create-table \
      "${project_id}" "${instance_id}" "${TABLE}"
  run_example ./data_async_snippets async-apply \
      "${project_id}" "${instance_id}" "${TABLE}" "${APPLY_ROW_KEY}"
  run_example ./data_async_snippets async-bulk-apply \
      "${project_id}" "${instance_id}" "${TABLE}"
  run_example ./data_async_snippets async-read-rows \
      "${project_id}" "${instance_id}" "${TABLE}"
  run_example ./data_async_snippets async-read-rows-with-limit \
      "${project_id}" "${instance_id}" "${TABLE}"
  run_example ./data_async_snippets async-read-row \
      "${project_id}" "${instance_id}" "${TABLE}" "${APPLY_ROW_KEY}"

  run_example ./data_async_snippets async-apply \
      "${project_id}" "${instance_id}" "${TABLE}" "${CHECK_AND_MUTATE_ROW_KEY}"
  run_example ./data_async_snippets async-check-and-mutate \
      "${project_id}" "${instance_id}" "${TABLE}" "${CHECK_AND_MUTATE_ROW_KEY}"

  run_example ./data_async_snippets async-apply \
      "${project_id}" "${instance_id}" "${TABLE}" "${READ_MODIFY_WRITE_ROW_KEY}"
  run_example ./data_async_snippets async-read-modify-write \
      "${project_id}" "${instance_id}" "${TABLE}" "${READ_MODIFY_WRITE_ROW_KEY}"

  run_example ./table_admin_snippets delete-table \
      "${project_id}" "${instance_id}" "${TABLE}"

  # Verify that calling without a command produces the right exit status and
  # some kind of Usage message.
  run_example_usage ./data_async_snippets
}

################################################
# Run the Bigtable quick start example.
# Globals:
#   None
# Arguments:
#   project_id: the Google Cloud Storage project used in the test. Can be a
#       fake project when testing against the emulator, as the emulator creates
#       projects on demand. It must be a valid, existing instance when testing
#       against production.
#   instance_id: the Google Cloud Bigtable instance used in the test. Can be a
#       fake instance when testing against the emulator, as the emulator creates
#       instances on demand. It must be a valid, existing instance when testing
#       against production.
# Returns:
#   None
################################################
#
# This function allows us to keep a single place where all the examples are
# listed. We want to run these examples in the continuous integration builds
# because they rot otherwise.
run_quickstart_example() {
  local project_id=$1
  local instance_id=$2
  shift 2

  # Use the same table in all the tests.
  local -r TABLE="quickstart-tbl-${RANDOM}"

  # Run the example with an empty table, exercise the path where the row is
  # not found.
  run_example "${CBT_CMD}" -project "${project_id}" -instance "${instance_id}" \
      createtable "${TABLE}" "families=cf1"
  run_example ./bigtable_quickstart "${project_id}" "${instance_id}" "${TABLE}"

  # Use the Cloud Bigtable command-line tool to create a row, exercise the path
  # where the row is found.
  run_example "${CBT_CMD}" -project "${project_id}" -instance "${instance_id}" \
      set "${TABLE}" "r1" "cf1:greeting=Hello"
  run_example ./bigtable_quickstart "${project_id}" "${instance_id}" "${TABLE}"
  run_example ./table_admin_snippets delete-table \
      "${project_id}" "${instance_id}" "${TABLE}"

  # Verify that calling without a command produces the right exit status and
  # some kind of Usage message.
  run_example_usage ./bigtable_quickstart
}

################################################
# Run the Bigtable hello world for InstanceAdmin example.
# Globals:
#   None
# Arguments:
#   project_id: the Google Cloud Platform project used in the test. Can be a
#       fake project when testing against the emulator, as the emulator creates
#       projects on demand. It must be a valid, existing instance when testing
#       against production.
#   zone_id: a Google Cloud Platform zone with support for Cloud Bigtable.
# Returns:
#   None
################################################
run_hello_instance_admin_example() {
  local project_id=$1
  local zone_id=$2
  shift 2

  # Use the same table in all the tests.
  local -r RANDOM_INSTANCE_ID="it-${RANDOM}-${RANDOM}"
  local -r RANDOM_CLUSTER_ID="${RANDOM_INSTANCE_ID}-c1"

  run_example ./bigtable_hello_instance_admin \
      "${project_id}" "${RANDOM_INSTANCE_ID}" "${RANDOM_CLUSTER_ID}" \
      "${zone_id}"

  # Verify that calling without a command produces the right exit status and
  # some kind of Usage message.
  run_example_usage ./bigtable_hello_instance_admin
}

################################################
# Run the Bigtable hello world example.
# Globals:
#   None
# Arguments:
#   project_id: the Google Cloud Storage project used in the test. Can be a
#       fake project when testing against the emulator, as the emulator creates
#       projects on demand. It must be a valid, existing instance when testing
#       against production.
#   instance_id: the Google Cloud Bigtable instance used in the test. Can be a
#       fake instance when testing against the emulator, as the emulator creates
#       instances on demand. It must be a valid, existing instance when testing
#       against production.
# Returns:
#   None
################################################
#
# This function allows us to keep a single place where all the examples are
# listed. We want to run these examples in the continuous integration builds
# because they rot otherwise.
run_hello_world_example() {
  local project_id=$1
  local instance_id=$2
  shift 2

  # Use the same table in all the tests.
  local -r TABLE="hello-world-tbl-${RANDOM}"

  run_example ./bigtable_hello_world "${project_id}" "${instance_id}" "${TABLE}"

  # Verify that calling without a command produces the right exit status and
  # some kind of Usage message.
  run_example_usage ./bigtable_hello_world
}
