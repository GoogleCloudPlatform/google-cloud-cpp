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

if [[ -z "${PROJECT_ROOT+x}" ]]; then
  readonly PROJECT_ROOT="$(cd "$(dirname "$0")/../../.."; pwd)"
fi
source "${PROJECT_ROOT}/ci/travis/linux-config.sh"
source "${PROJECT_ROOT}/ci/define-dump-log.sh"

# Exit successfully (and silently) if there are no documents to upload.
if [[ "${GENERATE_DOCS:-}" != "yes" ]]; then
  # No documentation generated by this build, skip upload.
  exit 0
fi

if [[ -n "${KOKORO_GITHUB_PULL_REQUEST_NUMBER:-}" ]]; then
  # Do not push new documentation on PR builds.
  exit 0
fi

if [[ -z "${KOKORO_GFILE_DIR:-}" ]]; then
  echo "Will not upload documents as KOKORO_GFILE_DIR not set."
  exit 0
fi

if [[ ! -r "${KOKORO_GFILE_DIR}/github-io-upload-token" ]]; then
  echo "Will not upload documents as the upload token is not available."
  exit 0
fi

GH_TOKEN="$(cat "${KOKORO_GFILE_DIR}/github-io-upload-token")"
readonly GH_TOKEN

# Because Kokoro checks out the code in `detached HEAD` mode there is no easy
# way to discover what is the current branch (and Kokoro does not expose the
# branch as an enviroment variable, like other CI systems do). We use the
# following trick:
# - Find out the current commit using git rev-parse HEAD.
# - Find out what branches contain that commit.
# - Exclude "HEAD detached" branches (they are not really branches).
# - Typically this is the single branch that was checked out by Kokoro.
BRANCH="$(git branch --remote --no-color --contains "$(git rev-parse HEAD)" | \
    grep -v 'HEAD detached' || exit 0)"
BRANCH="${BRANCH/  /}"
BRANCH="${BRANCH/origin\//}"
readonly BRANCH

case "${BRANCH:-}" in
  master)
    subdir="latest"
    ;;
  v[0-9]\.*)
    subdir="${BRANCH/v/}"
    subdir="${subdir%.x%}"
    subdir="${subdir}.0}"
    ;;
  *)
    echo "Will not upload documents as the branch (${BRANCH}) is not a release branch nor 'master'."
    exit 0
    ;;
esac

echo "================================================================"
echo "Uploading generated Doxygen docs to github.io $(date)."

# The usual way to host documentation in ${GIT_NAME}.github.io/${PROJECT_NAME}
# is to create a branch (gh-pages) and post the documentation in that branch.
# We first do some general git configuration:

# Clone the gh-pages branch into a staging directory.
REPO_URL="$(git config remote.origin.url)"
readonly REPO_URL
if [[ ! -d cmake-out/github-io-staging ]]; then
  git clone -b gh-pages "${REPO_URL}" cmake-out/github-io-staging
else
  if [[ ! -d cmake-out/github-io-staging/.git ]]; then
    echo "github-io-staging exists but it is not a git repository."
    exit 1
  fi
  (cd cmake-out/github-io-staging && git checkout gh-pages && git pull)
fi

# Remove any previous content in the subdirectory used for this release. We will
# recover any unmodified files in a second.
(cd cmake-out/github-io-staging ; \
 git rm -qfr --ignore-unmatch \
   "latest/google/cloud/{bigtable,common,firestore,storage}")

# Copy the build results into the gh-pages clone.
cp -r "${BUILD_OUTPUT}/google/cloud/html/." \
    "cmake-out/github-io-staging/common/${subdir}"
for lib in bigtable firestore storage; do
  cp -r "${BUILD_OUTPUT}/google/cloud/${lib}html/." \
      "cmake-out/github-io-staging/${lib}/${subdir}"
done

cd cmake-out/github-io-staging
git config user.name "Google Cloud C++ Project Robot"
git config user.email "google-cloud-cpp-bot@users.noreply.github.com"
git add --all "latest"

if git diff --quiet HEAD; then
  echo "No changes to the documentation, skipping upload."
  exit 0
fi

git commit -q -m"Automatically generated documentation"

if [[ "${REPO_URL:0:8}" != "https://" ]]; then
  echo "Repository is not in https:// format, attempting push to ${REPO_URL}"
  git push
  exit 0
fi

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "Skipping documentation upload as GH_TOKEN is not configured."
  exit 0
fi

readonly REPO_REF=${REPO_URL/https:\/\/}
git push https://"${GH_TOKEN}@${REPO_REF}" gh-pages
