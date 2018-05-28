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

readonly BINDIR="$(dirname $0)"
source "${BINDIR}/colors.sh"

# This script is supposed to run inside a Docker container, see
# ci/build-linux.sh for the expected setup.  The /v directory is a volume
# pointing to a (clean-ish) checkout of google-cloud-cpp:
(cd /v ; ./ci/check-style.sh)

# Run the configure / compile / test cycle inside a docker image.
# This script is designed to work in the context created by the
# ci/Dockerfile.* build scripts.
readonly IMAGE="cached-${DISTRO}-${DISTRO_VERSION}"
readonly BUILD_DIR="build-output/${IMAGE}"

CMAKE_COMMAND="cmake"
if [ "${SCAN_BUILD}" = "yes" ]; then
  CMAKE_COMMAND="scan-build cmake"
fi

# Tweak configuration for TEST_INSTALL=yes builds.
cmake_install_flags=""
if [ "${TEST_INSTALL}" = "yes" ]; then
  cmake_install_flags=-DGOOGLE_CLOUD_CPP_GRPC_PROVIDER=package
fi

echo "travis_fold:start:configure-cmake"
${CMAKE_COMMAND} \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    ${cmake_install_flags} \
    ${CMAKE_FLAGS:-} \
    -H. \
    -B"${BUILD_DIR}"
echo "travis_fold:end:configure-cmake"

# If scan-build is enabled, we need to manually compile the dependencies;
# otherwise, the static analyzer finds issues in them, and there is no way to
# ignore them.  When scan-build is not enabled, this is still useful because
# we can fold the output in Travis and make the log more interesting.
echo "${COLOR_YELLOW}Started dependency build at: $(date)${COLOR_RESET}"
echo "travis_fold:start:build-dependencies"
cmake --build "${BUILD_DIR}" --target skip-scanbuild-targets -- -j ${NCPU}
echo "travis_fold:end:build-dependencies"
echo "${COLOR_YELLOW}Finished dependency build at: $(date)${COLOR_RESET}"

# If scan-build is enabled we build the smallest subset of things that is
# needed; otherwise, we pick errors from things we do not care about. With
# scan-build disabled we compile everything, to test the build as most
# developers will experience it.
echo "${COLOR_YELLOW}Started build at: $(date)${COLOR_RESET}"
${CMAKE_COMMAND} --build "${BUILD_DIR}" -- -j ${NCPU}
echo "${COLOR_YELLOW}Finished build at: $(date)${COLOR_RESET}"

# Run the tests and output any failures.
cd "${BUILD_DIR}"
ctest --output-on-failure

# Run the integration tests.
for subdir in bigtable storage; do
  echo
  echo "Running integration tests for ${subdir}"
  /v/${subdir}/ci/run_integration_tests.sh
done

# Test the install rule and that the installation works.
if [ "${TEST_INSTALL}" = "yes" ]; then
  echo
  echo "${COLOR_YELLOW}Testing install rule.${COLOR_RESET}"
  cmake --build . --target install
  echo
  echo "${COLOR_YELLOW}Test installed libraries using cmake(1).${COLOR_RESET}"
  readonly TEST_INSTALL_DIR=/v/ci/test-install
  readonly TEST_INSTALL_CMAKE_OUTPUT_DIR=/v/build-output/test-install-cmake
  readonly TEST_INSTALL_MAKE_OUTPUT_DIR=/v/build-output/test-install-make
  cmake -H"${TEST_INSTALL_DIR}" -B"${TEST_INSTALL_CMAKE_OUTPUT_DIR}"
  cmake --build "${TEST_INSTALL_CMAKE_OUTPUT_DIR}"
  echo
  echo "${COLOR_YELLOW}Test installed libraries using make(1).${COLOR_RESET}"
  mkdir -p "${TEST_INSTALL_MAKE_OUTPUT_DIR}"
  make -C "${TEST_INSTALL_MAKE_OUTPUT_DIR}" -f"${TEST_INSTALL_DIR}/Makefile" VPATH="${TEST_INSTALL_DIR}"
fi

# If document generation is enabled, run it now.
if [ "${GENERATE_DOCS}" = "yes" ]; then
  make doxygen-docs
fi

# Some of the sanitizers only emit errors and do not change the error code
# of the tests, find any such errors and report them as a build failure.
echo
echo -n "Searching for sanitizer errors in the test log: "
if grep -qe '/v/.*\.cc:[0-9][0-9]*' \
       Testing/Temporary/LastTest.log; then
  echo "${COLOR_RED}some sanitizer errors found."
  echo
  grep -e '/v/.*\.cc:[0-9][0-9]*' Testing/Temporary/LastTest.log
  echo "${COLOR_RESET}"
  exit 1
else
  echo "${COLOR_GREEN}no sanitizer errors found.${COLOR_RESET}"
fi

# Collect the output from the Clang static analyzer and provide instructions to
# the developers on how to do that locally.
if [ "${SCAN_BUILD:-}" = "yes" ]; then
  if [ -n "$(ls -1d /tmp/scan-build-* 2>/dev/null)" ]; then
    cp -r /tmp/scan-build-* /v/scan-build-output
  fi
  if [ -r scan-build-output/index.html ]; then
    cat <<_EOF_;

${COLOR_RED}
scan-build detected errors.  Please read the log for details. To
run scan-build locally and examine the HTML output install and configure Docker,
then run:

DISTRO=ubuntu DISTRO_VERSION=16.04 SCAN_BUILD=yes NCPU=8 TRAVIS_OS_NAME=linux CXX=clang++ CC=clang ./ci/build-linux.sh

The HTML output will be copied into the scan-build-output subdirectory.
${COLOR_RESET}
_EOF_
    exit 1
  else
    echo
    echo "${COLOR_GREEN}scan-build completed without errors.${COLOR_RESET}"
  fi
fi
