// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Generated by the Codegen C++ plugin.
// If you make any local changes, they will be lost.
// source: google/cloud/bigquery/storage/v1/storage.proto

#include "google/cloud/bigquery/bigquery_read_connection.gcpcxx.pb.h"
#include "google/cloud/bigquery/bigquery_read_options.gcpcxx.pb.h"
#include "google/cloud/bigquery/internal/bigquery_read_option_defaults.gcpcxx.pb.h"
#include "google/cloud/bigquery/internal/bigquery_read_stub_factory.gcpcxx.pb.h"
#include "google/cloud/internal/resumable_streaming_read_rpc.h"
#include "google/cloud/internal/retry_loop.h"
#include "google/cloud/internal/streaming_read_rpc_logging.h"
#include <memory>

namespace google {
namespace cloud {
namespace bigquery {
inline namespace GOOGLE_CLOUD_CPP_GENERATED_NS {

BigQueryReadConnection::~BigQueryReadConnection() = default;

StatusOr<::google::cloud::bigquery::storage::v1::ReadSession>
BigQueryReadConnection::CreateReadSession(
    ::google::cloud::bigquery::storage::v1::CreateReadSessionRequest const&) {
  return Status(StatusCode::kUnimplemented, "not implemented");
}

StreamRange<::google::cloud::bigquery::storage::v1::ReadRowsResponse>
BigQueryReadConnection::ReadRows(
    ::google::cloud::bigquery::storage::v1::ReadRowsRequest const&) {
  return google::cloud::internal::MakeStreamRange<
      ::google::cloud::bigquery::storage::v1::ReadRowsResponse>(
      []() -> absl::variant<
               Status,
               ::google::cloud::bigquery::storage::v1::ReadRowsResponse> {
        return Status(StatusCode::kUnimplemented, "not implemented");
      });
}

StatusOr<::google::cloud::bigquery::storage::v1::SplitReadStreamResponse>
BigQueryReadConnection::SplitReadStream(
    ::google::cloud::bigquery::storage::v1::SplitReadStreamRequest const&) {
  return Status(StatusCode::kUnimplemented, "not implemented");
}

namespace {
class BigQueryReadConnectionImpl : public BigQueryReadConnection {
 public:
  BigQueryReadConnectionImpl(
      std::shared_ptr<bigquery_internal::BigQueryReadStub> stub,
      Options const& options)
      : stub_(std::move(stub)),
        retry_policy_prototype_(
            options.get<BigQueryReadRetryPolicyOption>()->clone()),
        backoff_policy_prototype_(
            options.get<BigQueryReadBackoffPolicyOption>()->clone()),
        idempotency_policy_(
            options.get<BigQueryReadConnectionIdempotencyPolicyOption>()
                ->clone()) {}

  ~BigQueryReadConnectionImpl() override = default;

  StatusOr<::google::cloud::bigquery::storage::v1::ReadSession>
  CreateReadSession(
      ::google::cloud::bigquery::storage::v1::CreateReadSessionRequest const&
          request) override {
    return google::cloud::internal::RetryLoop(
        retry_policy_prototype_->clone(), backoff_policy_prototype_->clone(),
        idempotency_policy_->CreateReadSession(request),
        [this](grpc::ClientContext& context,
               ::google::cloud::bigquery::storage::v1::
                   CreateReadSessionRequest const& request) {
          return stub_->CreateReadSession(context, request);
        },
        request, __func__);
  }

  StreamRange<::google::cloud::bigquery::storage::v1::ReadRowsResponse>
  ReadRows(::google::cloud::bigquery::storage::v1::ReadRowsRequest const&
               request) override {
    auto stub = stub_;
    auto retry_policy = std::shared_ptr<BigQueryReadRetryPolicy const>(
        retry_policy_prototype_->clone());
    auto backoff_policy = std::shared_ptr<BackoffPolicy const>(
        backoff_policy_prototype_->clone());

    auto factory =
        [stub](::google::cloud::bigquery::storage::v1::ReadRowsRequest const&
                   request) {
          auto context = absl::make_unique<grpc::ClientContext>();
          return stub->ReadRows(std::move(context), request);
        };

    auto resumable = internal::MakeResumableStreamingReadRpc<
        ::google::cloud::bigquery::storage::v1::ReadRowsResponse,
        ::google::cloud::bigquery::storage::v1::ReadRowsRequest>(
        retry_policy->clone(), backoff_policy->clone(),
        [](std::chrono::milliseconds) {}, factory,
        BigQueryReadReadRowsStreamingUpdater, request);

    return internal::MakeStreamRange(
        internal::StreamReader<
            ::google::cloud::bigquery::storage::v1::ReadRowsResponse>(
            [resumable] { return resumable->Read(); }));
  }

  StatusOr<::google::cloud::bigquery::storage::v1::SplitReadStreamResponse>
  SplitReadStream(
      ::google::cloud::bigquery::storage::v1::SplitReadStreamRequest const&
          request) override {
    return google::cloud::internal::RetryLoop(
        retry_policy_prototype_->clone(), backoff_policy_prototype_->clone(),
        idempotency_policy_->SplitReadStream(request),
        [this](grpc::ClientContext& context,
               ::google::cloud::bigquery::storage::v1::
                   SplitReadStreamRequest const& request) {
          return stub_->SplitReadStream(context, request);
        },
        request, __func__);
  }

 private:
  std::shared_ptr<bigquery_internal::BigQueryReadStub> stub_;
  std::unique_ptr<BigQueryReadRetryPolicy const> retry_policy_prototype_;
  std::unique_ptr<BackoffPolicy const> backoff_policy_prototype_;
  std::unique_ptr<BigQueryReadConnectionIdempotencyPolicy> idempotency_policy_;
};
}  // namespace

std::shared_ptr<BigQueryReadConnection> MakeBigQueryReadConnection(
    Options options) {
  options = bigquery_internal::BigQueryReadDefaultOptions(std::move(options));
  return std::make_shared<BigQueryReadConnectionImpl>(
      bigquery_internal::CreateDefaultBigQueryReadStub(options), options);
}

std::shared_ptr<BigQueryReadConnection> MakeBigQueryReadConnection(
    std::shared_ptr<bigquery_internal::BigQueryReadStub> stub,
    Options options) {
  options = bigquery_internal::BigQueryReadDefaultOptions(std::move(options));
  return std::make_shared<BigQueryReadConnectionImpl>(std::move(stub),
                                                      std::move(options));
}

}  // namespace GOOGLE_CLOUD_CPP_GENERATED_NS
}  // namespace bigquery
}  // namespace cloud
}  // namespace google
