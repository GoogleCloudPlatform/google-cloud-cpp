// Copyright 2018 Google LLC
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

#ifndef GOOGLE_CLOUD_CPP_STORAGE_CLIENT_INTERNAL_GOOGLE_APPLICATION_DEFAULT_CREDENTIALS_FILE_H_
#define GOOGLE_CLOUD_CPP_STORAGE_CLIENT_INTERNAL_GOOGLE_APPLICATION_DEFAULT_CREDENTIALS_FILE_H_

#include "google/cloud/storage/credentials.h"

namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
/// Return the path for the default service account credentials file.
std::string GoogleApplicationDefaultCredentialsFile();

/// The name of the environment variable to configure `HOME`.
char const* GoogleApplicationDefaultCredentialsHomeVariable();

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage

#endif  // GOOGLE_CLOUD_CPP_STORAGE_CLIENT_INTERNAL_GOOGLE_APPLICATION_DEFAULT_CREDENTIALS_FILE_H_
