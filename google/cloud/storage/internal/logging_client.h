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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_LOGGING_CLIENT_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_LOGGING_CLIENT_H_

#include "google/cloud/storage/internal/raw_client.h"

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
/**
 * A decorator for `storage::Client` that retries operations using policies.
 */
class LoggingClient : public RawClient {
 public:
  explicit LoggingClient(std::shared_ptr<RawClient> client);
  ~LoggingClient() override = default;

  ClientOptions const& client_options() const override;

  std::pair<Status, BucketMetadata> GetBucketMetadata(
      internal::GetBucketMetadataRequest const& request) override;

  std::pair<Status, ObjectMetadata> InsertObjectMedia(
      internal::InsertObjectMediaRequest const& request) override;

  std::pair<Status, ReadObjectRangeResponse> ReadObjectRangeMedia(
      internal::ReadObjectRangeRequest const&) override;

  std::pair<Status, internal::ListObjectsResponse> ListObjects(
      internal::ListObjectsRequest const&) override;

 private:
  std::shared_ptr<RawClient> client_;
};

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_LOGGING_CLIENT_H_
