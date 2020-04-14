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

if [[ $# != 2 ]]; then
  echo "Usage: $(basename "$0") <cache-folder> <cache-name>"
  exit 1
fi

if [[ -z "${PROJECT_ROOT+x}" ]]; then
  readonly PROJECT_ROOT="$(cd "$(dirname "$0")/../../.."; pwd)"
fi
GCLOUD=gcloud
source "${PROJECT_ROOT}/ci/colors.sh"
source "${PROJECT_ROOT}/ci/kokoro/gcloud-functions.sh"

readonly CACHE_FOLDER="$1"
readonly CACHE_NAME="$2"

KOKORO_GFILE_DIR="${KOKORO_GFILE_DIR:-/private/var/tmp}"
readonly KOKORO_GFILE_DIR

readonly KEYFILE="${KOKORO_GFILE_DIR}/build-results-service-account.json"
if [[ ! -f "${KEYFILE}" ]]; then
  echo "================================================================"
  log_normal "Service account for cache access is not configured."
  log_normal "No attempt will be made to upload the cache, exit with success."
  exit 0
fi

if [[ "${KOKORO_JOB_TYPE:-}" == "PRESUBMIT_GERRIT_ON_BORG" ]] || \
   [[ "${KOKORO_JOB_TYPE:-}" == "PRESUBMIT_GITHUB" ]]; then
  echo "================================================================"
  log_normal "Cache not updated as this is a PR build."
  exit 0
fi

readonly CCACHE_DIR="${HOME}/.ccache"

maybe_dirs=("${CCACHE_DIR}")
readonly BAZEL_BIN="$HOME/bin/bazel"
if [[ -x "${BAZEL_BIN}" ]]; then
  maybe_dirs+=("$("${BAZEL_BIN}" info repository_cache)")
  maybe_dirs+=("$("${BAZEL_BIN}" info output_base)")
fi

dirs=()
for dir in "${maybe_dirs[@]}"; do
  if [[ -d "${dir}"  ]]; then dirs+=("${dir}"); fi
done

readonly UPLOAD="cmake-out/upload"
mkdir -p "${UPLOAD}"

echo "================================================================"
log_normal "Preparing cache tarball for ${CACHE_NAME}"
tar -C / -zcf "${UPLOAD}/${CACHE_NAME}.tar.gz" "${dirs[@]}"

echo "================================================================"
log_normal "Uploading build cache ${CACHE_NAME} to ${CACHE_FOLDER}"

trap cleanup EXIT
cleanup() {
  revoke_service_account_keyfile "${KEYFILE}" || true
  delete_gcloud_config
}

create_gcloud_config
activate_service_account_keyfile "${KEYFILE}"
gsutil -q cp "${UPLOAD}/${CACHE_NAME}.tar.gz" "gs://${CACHE_FOLDER}/"

echo "================================================================"
log_normal "Upload completed"

exit 0
