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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_HANDLE_FACTORY_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_HANDLE_FACTORY_H_

#include "google/cloud/storage/internal/curl_wrappers.h"
#include <mutex>
#include <vector>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
/**
 * Implement the Factory Pattern for CURL handles (and multi-handles).
 */
class CurlHandleFactory {
 public:
  virtual ~CurlHandleFactory() = default;

  virtual CurlPtr CreateHandle() = 0;
  virtual void CleanupHandle(CurlPtr&&) = 0;

  virtual CurlMulti CreateMultiHandle() = 0;
  virtual void CleanupMultiHandle(CurlMulti&&) = 0;
};

std::shared_ptr<CurlHandleFactory> GetDefaultCurlHandleFactory();

/**
 * The default CurlHandleFactory: always init and cleanup.
 *
 * This implementation of the CurlHandleFactory does not
 */
class DefaultCurlHandleFactory : public CurlHandleFactory {
 public:
  DefaultCurlHandleFactory() = default;

  CurlPtr CreateHandle() override;
  void CleanupHandle(CurlPtr&&) override;

  CurlMulti CreateMultiHandle() override;
  void CleanupMultiHandle(CurlMulti&&) override;
};

/**
 * The default CurlHandleFactory: always init and cleanup.
 *
 * This implementation of the CurlHandleFactory does not
 */
class PooledCurlHandleFactory : public CurlHandleFactory {
 public:
  explicit PooledCurlHandleFactory(std::size_t maximum_size);
  ~PooledCurlHandleFactory() override;

  CurlPtr CreateHandle() override;
  void CleanupHandle(CurlPtr&&) override;

  CurlMulti CreateMultiHandle() override;
  void CleanupMultiHandle(CurlMulti&&) override;

 private:
  std::size_t maximum_size_;
  std::mutex mu_;
  std::vector<CURL*> handles_;
  std::vector<CURLM*> multi_handles_;
};

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_CURL_HANDLE_FACTORY_H_
