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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_ASYNC_OPERATION_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_ASYNC_OPERATION_H_

#include "google/cloud/bigtable/version.h"

namespace google {
namespace cloud {
namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
namespace internal {
class CompletionQueueImpl;
}  // namespace internal

/**
 * Represents a pending asynchronous operation.
 *
 * When applications create an asynchronous operations with a `CompletionQueue`
 * they provide a callback to be invoked when the operation completes
 * (successfully or not). The completion queue type-erases the callback and
 * hides it in a class derived from `AsyncOperation`.  A shared pointer to the
 * `AsyncOperation` is returned by the completion queue so library developers
 * can cancel the operation if needed.
 */
class AsyncOperation {
 public:
  virtual ~AsyncOperation() = default;

  /**
   * Requests that the operation be canceled.
   *
   * The result of canceling the operation is reported via the callback
   * registered when the operation was created.
   */
  virtual void Cancel() = 0;

  enum Disposition {
    CANCELLED,
    COMPLETED,
  };

 private:
  friend class internal::CompletionQueueImpl;
  /**
   * Notifies the application that the operation completed.
   *
   * Derived classes wrap the callbacks provided by the application and invoke
   * the callback when this virtual member function is called.
   *
   * @param ok true if the operation completed, false if the operation was
   *   canceled. Note that errors are a "normal" completion.
   */
  virtual void Notify(Disposition disposition) = 0;
};

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_ASYNC_OPERATION_H_
