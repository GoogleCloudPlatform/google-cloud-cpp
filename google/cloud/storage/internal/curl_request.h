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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_REQUEST_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_REQUEST_H

#include "google/cloud/storage/internal/curl_handle.h"
#include "google/cloud/storage/internal/curl_handle_factory.h"
#include "google/cloud/storage/internal/http_response.h"
#include "google/cloud/storage/version.h"

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
extern "C" std::size_t CurlRequestOnWriteData(char* ptr, size_t size,
                                              size_t nmemb, void* userdata);
extern "C" std::size_t CurlRequestOnHeaderData(char* contents, std::size_t size,
                                               std::size_t nitems,
                                               void* userdata);

class CurlRequest {
 public:
  CurlRequest() = default;
  ~CurlRequest() {
    if (!factory_) return;
    factory_->CleanupHandle(std::move(handle_));
  }

  CurlRequest(CurlRequest&&) = default;
  CurlRequest& operator=(CurlRequest&&) = default;

  /**
   * Makes the prepared request.
   *
   * This function can be called multiple times on the same request.
   *
   * @return The response HTTP error code, the headers and an empty payload.
   */
  StatusOr<HttpResponse> MakeRequest(std::string const& payload);

 private:
  friend class CurlRequestBuilder;
  friend std::size_t CurlRequestOnWriteData(char* ptr, size_t size,
                                            size_t nmemb, void* userdata);
  friend std::size_t CurlRequestOnHeaderData(char* contents, std::size_t size,
                                             std::size_t nitems,
                                             void* userdata);

  std::size_t OnWriteData(char* contents, std::size_t size, std::size_t nmemb);
  std::size_t OnHeaderData(char* contents, std::size_t size,
                           std::size_t nitems);

  std::string url_;
  CurlHeaders headers_ = CurlHeaders(nullptr, &curl_slist_free_all);
  std::string user_agent_;
  std::string response_payload_;
  CurlReceivedHeaders received_headers_;
  bool logging_enabled_ = false;
  CurlHandle::SocketOptions socket_options_;
  CurlHandle handle_;
  std::shared_ptr<CurlHandleFactory> factory_;
};

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_REQUEST_H
