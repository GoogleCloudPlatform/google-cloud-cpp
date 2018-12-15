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

#include "google/cloud/storage/internal/noex_client.h"
#include "google/cloud/storage/internal/curl_client.h"

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace noex {

static_assert(std::is_copy_constructible<storage::noex::Client>::value,
              "storage::noex::Client must be copy constructible");
static_assert(std::is_copy_assignable<storage::noex::Client>::value,
              "storage::noex::Client must be copy assignable");

std::shared_ptr<internal::RawClient> Client::CreateDefaultClient(
    ClientOptions options) {
  // TODO(#1694) - remove all the code duplicated in `storage::Client`.
  return internal::CurlClient::Create(std::move(options));
}

}  // namespace noex
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
