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

# Make our include guard clean against set -o nounset.
test -n "${CI_ETC_INSTALL_CONFIG_SH__:-}" || declare -i CI_ETC_INSTALL_CONFIG_SH__=0
if ((CI_ETC_INSTALL_CONFIG_SH__++ != 0)); then
  return 0
fi # include guard

GOOGLE_CLOUD_CPP_BAZEL_VERSION="3.7.1"
readonly GOOGLE_CLOUD_CPP_BAZEL_VERSION

GOOGLE_CLOUD_CPP_CLOUD_SDK_VERSION="316.0.0"
readonly GOOGLE_CLOUD_CPP_CLOUD_SDK_VERSION

GOOGLE_CLOUD_CPP_SDK_SHA256="96a0b75474dbfa9f3d46dcdec7a4d68a664cb7d57fade5710fe88b1fdf6babb3"
readonly GOOGLE_CLOUD_CPP_SDK_SHA256
