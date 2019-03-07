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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_HMAC_KEY_REQUESTS_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_HMAC_KEY_REQUESTS_H_

#include "google/cloud/storage/hmac_key_metadata.h"
#include "google/cloud/storage/internal/generic_request.h"
#include "google/cloud/storage/internal/http_response.h"
#include "google/cloud/storage/internal/nljson.h"
#include <iosfwd>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {

struct HmacKeyMetadataParser {
  static StatusOr<HmacKeyMetadata> FromJson(internal::nl::json const& json);
  static StatusOr<HmacKeyMetadata> FromString(std::string const& payload);
};

/// Represents a request to create a call the `HmacKeys: insert` API.
class CreateHmacKeyRequest : public GenericRequest<CreateHmacKeyRequest> {
 public:
  CreateHmacKeyRequest() = default;
  CreateHmacKeyRequest(std::string project_id, std::string service_account)
      : project_id_(std::move(project_id)),
        service_account_(std::move(service_account)) {}

  std::string const& project_id() const { return project_id_; }
  std::string const& service_account() const { return service_account_; }

 private:
  std::string project_id_;
  std::string service_account_;
};

std::ostream& operator<<(std::ostream& os, CreateHmacKeyRequest const& r);

/// The response from a `HmacKeys: insert` API.
struct CreateHmacKeyResponse {
  static StatusOr<CreateHmacKeyResponse> FromHttpResponse(
      HttpResponse const& response);

  std::string kind;
  HmacKeyMetadata resource;
  std::string secret;
};

std::ostream& operator<<(std::ostream& os, CreateHmacKeyResponse const& r);

/// Represents a request to call the `HmacKeys: list` API.
class ListHmacKeysRequest
    : public GenericRequest<ListHmacKeysRequest, Deleted, MaxResults,
                            ServiceAccountFilter, UserProject> {
 public:
  explicit ListHmacKeysRequest(std::string project_id)
      : project_id_(std::move(project_id)) {}

  std::string const& project_id() const { return project_id_; }
  std::string const& page_token() const { return page_token_; }
  ListHmacKeysRequest& set_page_token(std::string page_token) {
    page_token_ = std::move(page_token);
    return *this;
  }

 private:
  std::string project_id_;
  std::string page_token_;
};

std::ostream& operator<<(std::ostream& os, ListHmacKeysRequest const& r);

/// Represents a response to the `HmacKeys: list` API.
struct ListHmacKeysResponse {
  static StatusOr<ListHmacKeysResponse> FromHttpResponse(
      HttpResponse const& response);

  std::string next_page_token;
  std::vector<HmacKeyMetadata> items;
};

std::ostream& operator<<(std::ostream& os, ListHmacKeysResponse const& r);

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_HMAC_KEY_REQUESTS_H_
