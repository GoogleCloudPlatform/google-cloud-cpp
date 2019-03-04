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

"""Load dependencies needed to compile and test the google-cloud-cpp library."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

def google_cloud_cpp_deps():
    """Loads dependencies need to compile the google-cloud-cpp library.

    Application developers can call this function from their WORKSPACE file
    to obtain all the necessary dependencies for google-cloud-cpp, including
    gRPC and its dependencies. This function only loads dependencies that
    have not been previously loaded, allowing application developers to
    override the version of the dependencies they want to use.
    """

    # Load a newer version of google test than what gRPC does.
    if "com_google_googletest" not in native.existing_rules():
        http_archive(
            name = "com_google_googletest",
            strip_prefix = "googletest-b6cd405286ed8635ece71c72f118e659f4ade3fb",
            urls = [
                "https://github.com/google/googletest/archive/b6cd405286ed8635ece71c72f118e659f4ade3fb.tar.gz",
            ],
            sha256 = "8d9aa381a6885fe480b7d0ce8ef747a0b8c6ee92f99d74ab07e3503434007cb0",
        )

    # Load the googleapis dependency.
    if "com_github_googleapis_googleapis" not in native.existing_rules():
        http_archive(
            name = "com_github_googleapis_googleapis",
            urls = [
                "https://github.com/google/googleapis/archive/6a3277c0656219174ff7c345f31fb20a90b30b97.zip",
            ],
            strip_prefix = "googleapis-6a3277c0656219174ff7c345f31fb20a90b30b97",
            sha256 = "82ba91a41fb01305de4e8805c0a9270ed2035007161aa5a4ec60f887a499f5e9",
            build_file = "@com_github_googleapis_google_cloud_cpp//bazel:googleapis.BUILD",
        )

    # Load gRPC and its dependencies, using a similar pattern to this function.
    # This implictly loads "com_google_protobuf", which we use.
    if "com_github_grpc_grpc" not in native.existing_rules():
        http_archive(
            name = "com_github_grpc_grpc",
            strip_prefix = "grpc-046e3e4ab5cdb867bda7a5c40fd9b0ac84ad0ff8",
            urls = [
                "https://github.com/grpc/grpc/archive/046e3e4ab5cdb867bda7a5c40fd9b0ac84ad0ff8.tar.gz",
                "https://mirror.bazel.build/github.com/grpc/grpc/archive/046e3e4ab5cdb867bda7a5c40fd9b0ac84ad0ff8.tar.gz",
            ],
            sha256 = "9a0ee9f59df481e2516deb59e3ccd1f973b023dab0e1be41cd30db56aea4b6cc",
        )

    # Load OpenCensus.
    if "io_opencensus_cpp" not in native.existing_rules():
        http_archive(
            name = "io_opencensus_cpp",
            strip_prefix = "opencensus-cpp-03dff0352522983ffdee48cedbf87cbe37f1bb7f",
            urls = [
                "https://github.com/census-instrumentation/opencensus-cpp/archive" +
                "/03dff0352522983ffdee48cedbf87cbe37f1bb7f.tar.gz",
            ],
            sha256 = "8cbff4b73121d255c92aa91582af63f86b3c3e5da53fe5a0a55097b6abeb6157",
        )

    # We need libcurl for the Google Cloud Storage client.
    if "com_github_curl_curl" not in native.existing_rules():
        http_archive(
            name = "com_github_curl_curl",
            urls = [
                "https://mirror.bazel.build/curl.haxx.se/download/curl-7.60.0.tar.gz",
                "https://curl.haxx.se/download/curl-7.60.0.tar.gz",
            ],
            strip_prefix = "curl-7.60.0",
            sha256 = "e9c37986337743f37fd14fe8737f246e97aec94b39d1b71e8a5973f72a9fc4f5",
            build_file = "@com_github_googleapis_google_cloud_cpp//bazel:curl.BUILD",
        )

    # We need the nlohmann_json library
    if "com_github_nlohmann_json_single_header" not in native.existing_rules():
        http_file(
            name = "com_github_nlohmann_json_single_header",
            urls = [
                "https://github.com/nlohmann/json/releases/download/v3.4.0/json.hpp",
            ],
            sha256 = "63da6d1f22b2a7bb9e4ff7d6b255cf691a161ff49532dcc45d398a53e295835f",
        )

    # Load google/crc32c, a library to efficiently compute CRC32C checksums.
    if "com_github_google_crc32c" not in native.existing_rules():
        http_archive(
            name = "com_github_google_crc32c",
            strip_prefix = "crc32c-1.0.6",
            urls = [
                "https://github.com/google/crc32c/archive/1.0.6.tar.gz",
            ],
            sha256 = "6b3b1d861bb8307658b2407bc7a4c59e566855ef5368a60b35c893551e4788e9",
            build_file = "@com_github_googleapis_google_cloud_cpp//bazel:crc32c.BUILD",
        )

    # We use the cc_proto_library() rule from @com_google_protobuf, which
    # assumes that grpc_cpp_plugin and grpc_lib are in the //external: module
    native.bind(
        name = "grpc_cpp_plugin",
        actual = "@com_github_grpc_grpc//:grpc_cpp_plugin",
    )

    native.bind(
        name = "grpc_lib",
        actual = "@com_github_grpc_grpc//:grpc++",
    )
