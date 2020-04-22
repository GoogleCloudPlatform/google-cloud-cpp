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

if [[ $# != 3 ]]; then
  echo "Usage: $(basename "$0") <cache-folder> <cache-name> <home-directory>"
  exit 1
fi

if [[ -z "${PROJECT_ROOT+x}" ]]; then
  readonly PROJECT_ROOT="$(
    cd "$(dirname "$0")/../../.."
    pwd
  )"
fi
GCLOUD=gcloud
source "${PROJECT_ROOT}/ci/colors.sh"
source "${PROJECT_ROOT}/ci/kokoro/gcloud-functions.sh"

readonly CACHE_FOLDER="$1"
readonly CACHE_NAME="$2"
readonly HOME_DIR="$3"

readonly KEYFILE="${KOKORO_GFILE_DIR:-/dev/shm}/build-results-service-account.json"
if [[ ! -f "${KEYFILE}" ]]; then
  echo "================================================================"
  log_normal "Service account for cache access is not configured."
  log_normal "No attempt will be made to upload the cache, exit with success."
  exit 0
fi

if [[ "${RUNNING_CI:-}" != "yes" || "${KOKORO_JOB_TYPE:-}" != "CONTINUOUS_INTEGRATION" ]]; then
  echo "================================================================"
  log_normal "Cache not updated as this is not a CI build or it is a PR build."
  exit 0
fi

maybe_dirs=(
  # This is where ccache stores its files, if present we want to back it up
  "${HOME_DIR}/.ccache"

  # The quickstart builds need to preserve the contents of the vcpkg installed/
  # directory, but we have to separate it from the other files in `vcpkg` or
  # things like `git clone` do not work as expected.
  "${HOME_DIR}/vcpkg-quickstart-cache"

  # Bazel, when running inside the Docker container, puts its cache here:
  "${HOME_DIR}/.cache"
)

dirs=()
for dir in "${maybe_dirs[@]}"; do
  if [[ -d "${dir}" ]]; then dirs+=("${dir}"); fi
done

echo "================================================================"
log_normal "Preparing cache tarball for ${CACHE_NAME}"
tar -zcf "${HOME_DIR}/${CACHE_NAME}.tar.gz" "${dirs[@]}"

echo "================================================================"
log_normal "Uploading build cache ${CACHE_NAME} to ${CACHE_FOLDER}"

trap cleanup EXIT
cleanup() {
  revoke_service_account_keyfile "${KEYFILE}" || true
  delete_gcloud_config
}

create_gcloud_config
activate_service_account_keyfile "${KEYFILE}"
env "CLOUDSDK_ACTIVE_CONFIG_NAME=${GCLOUD_CONFIG}" \
  gsutil -q cp "${HOME_DIR}/${CACHE_NAME}.tar.gz" "gs://${CACHE_FOLDER}/"

echo "================================================================"
log_normal "Upload completed"

exit 0
