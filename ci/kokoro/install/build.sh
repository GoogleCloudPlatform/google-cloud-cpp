#!/usr/bin/env bash
# Copyright 2019 Google LLC
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
source module /ci/lib/io.sh

if [[ $# -eq 1 ]]; then
  export DISTRO="${1}"
elif [[ -n "${KOKORO_JOB_NAME:-}" ]]; then
  # Kokoro injects the KOKORO_JOB_NAME environment variable, the value of this
  # variable is cloud-cpp/<repo>/<config-file-name-without-cfg> (or more
  # generally <path/to/config-file-without-cfg>). By convention we name these
  # files `$foo.cfg` for continuous builds and `$foo-presubmit.cfg` for
  # presubmit builds. Here we extract the value of "foo" and use it as the build
  # name.
  DISTRO="$(basename "${KOKORO_JOB_NAME}" "-presubmit")"
  export DISTRO

  # This is passed into the environment of the docker build and its scripts to
  # tell them if they are running as part of a CI build rather than just a
  # human invocation of "build.sh <build-name>". This allows scripts to be
  # strict when run in a CI, but a little more friendly when run by a human.
  RUNNING_CI="yes"
  export RUNNING_CI
else
  echo "Aborting build as the distribution name is not defined."
  echo "If you are invoking this script via the command line use:"
  echo "    $0 <distro-name>"
  echo
  echo "If this script is invoked by Kokoro, the CI system is expected to set"
  echo "the KOKORO_JOB_NAME environment variable."
  exit 1
fi

echo "================================================================"
io::log "Load Google Container Registry configuration parameters."
source module /ci/kokoro/lib/docker-variables.sh
source module /ci/kokoro/lib/gcloud.sh
source module /ci/kokoro/lib/cache.sh

echo "================================================================"
io::log_yellow "Change working directory to project root."
cd "${PROJECT_ROOT}"

echo "================================================================"
io::log "Building with ${NCPU} cores on ${PWD}."

echo "================================================================"
io::log "Setup Google Container Registry access."
if [[ -f "${KOKORO_GFILE_DIR:-}/gcr-service-account.json" ]]; then
  gcloud auth activate-service-account --key-file \
    "${KOKORO_GFILE_DIR}/gcr-service-account.json"
fi
gcloud auth configure-docker

echo "================================================================"
io::log "Download existing image (if available) for ${DISTRO}."
has_cache="false"
if docker pull "${INSTALL_IMAGE}:latest"; then
  echo "Existing image successfully downloaded."
  has_cache="true"
fi

readonly CACHE_BUCKET="${GOOGLE_CLOUD_CPP_KOKORO_RESULTS:-cloud-cpp-kokoro-results}"
readonly CACHE_FOLDER="${CACHE_BUCKET}/build-cache/google-cloud-cpp/main/install"
readonly CACHE_NAME="${DISTRO}.tar.gz"

if cache_download_enabled; then
  mkdir -p ci/kokoro/install/ccache-contents
  cache_download_tarball \
    "${CACHE_FOLDER}" "ci/kokoro/install/ccache-contents" "${CACHE_NAME}" || true
fi

echo "================================================================"
io::log "Build base image with minimal development tools for ${DISTRO}."
update_cache="false"

devtools_flags=(
  # Only build up to the stage that installs the minimal development tools, but
  # does not compile any of our code.
  "--target" "devtools"
  # Create the image with the same tag as the cache we are using, so we can
  # upload it.
  "-t" "${INSTALL_IMAGE}:latest"
  "--build-arg" "NCPU=${NCPU}"
  "-f" "ci/kokoro/install/Dockerfile.${DISTRO}"
)

if "${has_cache}"; then
  devtools_flags+=("--cache-from=${INSTALL_IMAGE}:latest")
fi

if [[ "${RUNNING_CI:-}" == "yes" ]] &&
  [[ -z "${KOKORO_GITHUB_PULL_REQUEST_NUMBER:-}" ]]; then
  devtools_flags+=("--no-cache")
fi

io::log "Running docker build with " "${devtools_flags[@]}"
if docker build "${devtools_flags[@]}" ci; then
  update_cache="true"
fi

if "${update_cache}" && [[ "${RUNNING_CI:-}" == "yes" ]] &&
  [[ -z "${KOKORO_GITHUB_PULL_REQUEST_NUMBER:-}" ]]; then
  echo "================================================================"
  echo "Uploading updated base image for ${DISTRO} $(date)."
  # Do not stop the build on a failure to update the cache.
  docker push "${INSTALL_IMAGE}:latest" || true
fi

echo "================================================================"
io::log_yellow "Compile and install the code and the quickstart programs."
readonly INSTALL_RUN_IMAGE="${DOCKER_IMAGE_PREFIX}/ci-install-runtime-${DISTRO}"
docker build -t "${INSTALL_RUN_IMAGE}" \
  "--cache-from=${INSTALL_IMAGE}:latest" \
  "--target=install" \
  "--build-arg" "NCPU=${NCPU}" \
  "--build-arg" "DISTRO=${DISTRO}" \
  -f "ci/kokoro/install/Dockerfile.${DISTRO}" .

echo "================================================================"
io::log_yellow "Run quickstart programs."
source module /ci/kokoro/install/lib/run-installed-programs.sh

echo
io::log_green "Build successful."

set +e
if ! cache_upload_enabled; then
  exit 0
fi

echo "================================================================"
io::log "Preparing and uploading ccache tarball."
mkdir -p ci/kokoro/install/ccache-contents
docker run --rm --volume "$PWD:/v" \
  --workdir /h \
  "${INSTALL_RUN_IMAGE}:latest" \
  tar -zcf "/v/ci/kokoro/install/ccache-contents/${DISTRO}.tar.gz" .ccache
cache_upload_tarball "ci/kokoro/install/ccache-contents" "${DISTRO}.tar.gz" \
  "${CACHE_FOLDER}"

exit 0
