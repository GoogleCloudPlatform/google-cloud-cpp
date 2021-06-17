// Copyright 2021 Google LLC
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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_ASYNC_LONG_RUNNING_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_ASYNC_LONG_RUNNING_H

#include "google/cloud/backoff_policy.h"
#include "google/cloud/completion_queue.h"
#include "google/cloud/future.h"
#include "google/cloud/internal/async_polling_loop.h"
#include "google/cloud/internal/async_retry_loop.h"
#include "google/cloud/polling_policy.h"
#include "google/cloud/status_or.h"
#include "google/cloud/version.h"
#include "absl/functional/function_ref.h"
#include <google/longrunning/operations.pb.h>
#include <grpcpp/grpcpp.h>
#include <functional>
#include <memory>

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {
namespace internal {

/// Extracts the value (or error) from a completed long-running operation
Status ExtractOperationResultImpl(
    StatusOr<google::longrunning::Operation> op,
    google::protobuf::Message& result,
    absl::FunctionRef<bool(google::protobuf::Any const&)> validate_any,
    std::string const& location);

/**
 * Extracts the value from a completed long-running operation.
 *
 * This helper is used in `AsyncLongRunningOperation()` to extract the value (or
 * error) from a completed long-running operation.
 */
template <typename ReturnType>
StatusOr<ReturnType> ExtractLongRunningResult(
    StatusOr<google::longrunning::Operation> op, std::string const& location) {
  ReturnType result;
  auto status = ExtractOperationResultImpl(
      std::move(op), result,
      [](google::protobuf::Any const& any) { return any.Is<ReturnType>(); },
      location);
  if (!status.ok()) return status;
  return result;
}

/**
 * Asynchronously starts and polls a long-running operation.
 *
 * Long-running operations [aip/151] are used for API methods that take a
 * significant amount of time to complete (think minutes, maybe an hour). The
 * gRPC API returns a "promise" object, represented by the
 * `google::longrunning::Operation` proto, and the application (or client
 * library) should periodically poll this object until it is "done".
 *
 * In the C++ client libraries we represent these long-running operations by
 * a member function that returns `future<StatusOr<ReturnType>>` this function
 * is a helper to implement these member functions. It first starts the
 * operation using an asynchronous retry loop, and then starts an asynchronous
 * loop to poll the operation until it completes.
 *
 * The promise can complete with an error, which is represented by a
 * `google::cloud::Status` object, or with success and some `ReturnType` value.
 * The application may also configure the "polling policy", which may stop the
 * polling even though the operation has not completed.
 *
 * Library developers would use this function as follows:
 *
 * @code
 * class BarStub {
 *  public:
 *   virtual future<StatusOr<google::longrunning::Operation>> AsyncFoo(
 *     google::cloud::CompletionQueue& cq,
 *     std::unique_ptr<grpc::ClientContext> context,
 *     FooRequest const& request) = 0;
 *
 *   virtual future<StatusOr<google::longrunning::Operation>> AsyncGetOperation(
 *     google::cloud::CompletionQueue& cq,
 *     std::unique_ptr<grpc::ClientContext> context,
 *     google::longrunning::GetOperationRequest const& request) = 0;
 *
 *   virtual future<Status> AsyncGetOperation(
 *     google::cloud::CompletionQueue& cq,
 *     std::unique_ptr<grpc::ClientContext> context,
 *     google::longrunning::CancelOperationRequest const& request) = 0;
 * };
 * @endcode
 *
 * The corresponding `*ConnectionImpl` class would look as follows:
 *
 * @code
 * class BarConnectionImpl : public BarConnection {
 *  public:
 *   // Using C++14 for exposition purposes, the implementation supports C++11
 *   future<StatusOr<FooResponse>> Foo(FooRequest const& request) override {
 *     return google::cloud::internal::AsyncLongRunningLoop(
 *       cq_, request,
 *       [stub = stub_](auto& cq, auto context, auto const& request) {
 *         return stub->AsyncFoo(cq, std::move(context), request);
 *       },
 *       [stub = stub_](auto& cq, auto context, auto const& request) {
 *         return stub->AsyncGetOperation(cq, std::move(context), request);
 *       },
 *       [stub = stub_](auto& cq, auto context, auto const& request) {
 *         return stub->AsyncCancelOperation(cq, std::move(context), request);
 *       },
 *       retry_policy_->clone(), backoff_policy_->clone(),
 *       IdempotencyPolicy::kIdempotent,
 *       polling_policy_->clone(),
 *       __func__ // for debugging
 *       );
 *   }
 *
 *  private:
 *    google::cloud::CompletionQueue cq_;
 *    std::shared_ptr<BarStub> stub_;
 * };
 * @endcode
 *
 * [aip/151]: https://google.aip.dev/151
 */
template <typename ReturnType, typename RequestType, typename StartFunctor,
          typename RetryPolicyType>
future<StatusOr<ReturnType>> AsyncLongRunningOperation(
    google::cloud::CompletionQueue cq, RequestType&& request,
    StartFunctor&& start, AsyncPollLongRunningOperation poll,
    AsyncCancelLongRunningOperation cancel,
    std::unique_ptr<RetryPolicyType> retry_policy,
    std::unique_ptr<BackoffPolicy> backoff_policy, Idempotency idempotent,
    std::unique_ptr<PollingPolicy> polling_policy, char const* location) {
  auto operation =
      AsyncRetryLoop(std::move(retry_policy), std::move(backoff_policy),
                     idempotent, cq, std::forward<StartFunctor>(start),
                     std::forward<RequestType>(request), location);
  struct MoveCapture {
    google::cloud::CompletionQueue cq;
    AsyncPollLongRunningOperation poll;
    AsyncCancelLongRunningOperation cancel;
    std::unique_ptr<PollingPolicy> polling_policy;
    std::string location;

    future<StatusOr<ReturnType>> operator()(
        future<StatusOr<google::longrunning::Operation>> f) {
      auto op = f.get();
      if (!op) {
        return make_ready_future(StatusOr<ReturnType>(std::move(op).status()));
      }
      auto loc = this->location;
      return AsyncPollingLoop(std::move(cq), *std::move(op), std::move(poll),
                              std::move(cancel), std::move(polling_policy),
                              std::move(location))
          .then([loc](future<StatusOr<google::longrunning::Operation>> g) {
            return ExtractLongRunningResult<ReturnType>(g.get(), loc);
          });
    }
  };

  return operation.then(
      MoveCapture{std::move(cq), std::move(poll), std::move(cancel),
                  std::move(polling_policy), std::string{location}});
}

}  // namespace internal
}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_ASYNC_LONG_RUNNING_H
