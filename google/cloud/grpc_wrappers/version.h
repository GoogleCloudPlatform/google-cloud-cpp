// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_GRPC_WRAPPERS_VERSION_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_GRPC_WRAPPERS_VERSION_H_

#include "google/cloud/grpc_wrappers/version_info.h"
#include "google/cloud/version.h"
#include <string>

#define GRPC_WRAPPERS_NS                              \
  GOOGLE_CLOUD_CPP_VEVAL(GRPC_WRAPPERS_VERSION_MAJOR, \
                         GRPC_WRAPPERS_VERSION_MINOR)

namespace google {
namespace cloud {
/**
 * Contains all the Cloud C++ gRPC Wrappers APIs.
 */
namespace grpc_wrappers {
/**
 * The inlined, versioned namespace for the Cloud C++ gRPC Wrappers APIs.
 *
 * Applications may need to link multiple versions of the Cloud C++ gRPC
 * Wrappers for example, if they link a library that uses an older version of
 * the client than they do.  This namespace is inlined, so applications can use
 * `grpc_wrappers::Foo` in their source, but the symbols are versioned, i.e.,
 * the symbol becomes `grpc_wrappers::v1::Foo`.
 *
 * Note that, consistent with the semver.org guidelines, the v0 version makes
 * no guarantees with respect to backwards compatibility.
 */
inline namespace GRPC_WRAPPERS_NS {
/**
 * The Cloud C++ gRPC Wrappers major version.
 *
 * @see https://semver.org/spec/v2.0.0.html for details.
 */
int constexpr version_major() { return GRPC_WRAPPERS_VERSION_MAJOR; }

/**
 * The Cloud C++ gRPC Wrappers minor version.
 *
 * @see https://semver.org/spec/v2.0.0.html for details.
 */
int constexpr version_minor() { return GRPC_WRAPPERS_VERSION_MINOR; }

/**
 * The Cloud C++ gRPC Wrappers patch version.
 *
 * @see https://semver.org/spec/v2.0.0.html for details.
 */
int constexpr version_patch() { return GRPC_WRAPPERS_VERSION_PATCH; }

/// A single integer representing the Major/Minor/Patch version.
int constexpr version() {
  return 100 * (100 * version_major() + version_minor()) + version_patch();
}

/// The version as a string, in MAJOR.MINOR.PATCH+gitrev format.
std::string version_string();

}  // namespace GRPC_WRAPPERS_NS
}  // namespace grpc_wrappers
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_GRPC_WRAPPERS_VERSION_H_
