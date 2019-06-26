// Copyright 2019 Google LLC
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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_GAX_VERSION_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_GAX_VERSION_H_

#include "google/cloud/gax/version_info.h"
#include "google/cloud/version.h"
#include <string>

#define GAX_CPP_NS \
  GOOGLE_CLOUD_CPP_VEVAL(GAX_CPP_VERSION_MAJOR, GAX_CPP_VERSION_MINOR)

namespace google {
/**
 * Contains all the Cloud C++ Google API Extensions APIs.
 */
namespace gax {
/**
 * The inlined, versioned namespace for the Cloud C++ Google API Extension APIs.
 *
 * Applications may need to link multiple versions of the Cloud C++ Google
 * API Extensions for example, if they link a library that uses an older version
 * of the client than they do.  This namespace is inlined, so applications can
 * use `gax::Foo` in their source, but the symbols are versioned, i.e., the
 * symbol becomes `gax::v1::Foo`.
 *
 * Note that, consistent with the semver.org guidelines, the v0 version makes
 * no guarantees with respect to backwards compatibility.
 */
inline namespace GAX_CPP_NS {
/**
 * The Cloud C++ Google API Extensions major version.
 *
 * @see https://semver.org/spec/v2.0.0.html for details.
 */
int constexpr version_major() { return GAX_CPP_VERSION_MAJOR; }

/**
 * The Cloud C++ Google API Extensions minor version.
 *
 * @see https://semver.org/spec/v2.0.0.html for details.
 */
int constexpr version_minor() { return GAX_CPP_VERSION_MINOR; }

/**
 * The Cloud C++ Google API Extensions patch version.
 *
 * @see https://semver.org/spec/v2.0.0.html for details.
 */
int constexpr version_patch() { return GAX_CPP_VERSION_PATCH; }

/// A single integer representing the Major/Minor/Patch version.
int constexpr version() {
  return 100 * (100 * version_major() + version_minor()) + version_patch();
}

/// The version as a string, in MAJOR.MINOR.PATCH+gitrev format.
std::string version_string();

}  // namespace GAX_CPP_NS
}  // namespace gax
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_GAX_VERSION_H_
