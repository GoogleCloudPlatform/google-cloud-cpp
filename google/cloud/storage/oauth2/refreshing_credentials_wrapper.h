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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_OAUTH2_REFRESHING_CREDENTIALS_WRAPPER_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_OAUTH2_REFRESHING_CREDENTIALS_WRAPPER_H_

#include "google/cloud/storage/status.h"
#include <chrono>
#include <string>
#include <utility>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace oauth2 {
/**
 * Wrapper for refreshable parts of a Credentials object.
 */
class RefreshingCredentialsWrapper {
 public:
  template <typename RefreshFunctor>
  std::pair<storage::Status, std::string> AuthorizationHeader(
      RefreshFunctor refresh_fn) {
    if (IsValid()) {
      return std::make_pair(storage::Status(), authorization_header_);
    }

    storage::Status status = refresh_fn();
    return std::make_pair(status,
                          status.ok() ? authorization_header_ : std::string{});
  }

  bool IsExpired();

  bool IsValid();

  std::string authorization_header_;
  std::chrono::system_clock::time_point expiration_time_;
};

}  // namespace oauth2
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_OAUTH2_REFRESHING_CREDENTIALS_WRAPPER_H_
