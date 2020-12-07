// Copyright 2020 Google LLC
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
// source: google/iam/credentials/v1/iamcredentials.proto
#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_IAM_INTERNAL_IAM_CREDENTIALS_STUB_GCPCXX_PB_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_IAM_INTERNAL_IAM_CREDENTIALS_STUB_GCPCXX_PB_H

#include "google/cloud/status_or.h"
#include "google/cloud/version.h"
#include <google/iam/credentials/v1/iamcredentials.grpc.pb.h>
#include <memory>

namespace google {
namespace cloud {
namespace iam_internal {
inline namespace GOOGLE_CLOUD_CPP_NS {

class IAMCredentialsStub {
 public:
  virtual ~IAMCredentialsStub() = 0;

  virtual StatusOr<::google::iam::credentials::v1::GenerateAccessTokenResponse>
  GenerateAccessToken(
      grpc::ClientContext& context,
      ::google::iam::credentials::v1::GenerateAccessTokenRequest const&
          request) = 0;

  virtual StatusOr<::google::iam::credentials::v1::GenerateIdTokenResponse>
  GenerateIdToken(grpc::ClientContext& context,
                  ::google::iam::credentials::v1::GenerateIdTokenRequest const&
                      request) = 0;

  virtual StatusOr<::google::iam::credentials::v1::SignBlobResponse> SignBlob(
      grpc::ClientContext& context,
      ::google::iam::credentials::v1::SignBlobRequest const& request) = 0;

  virtual StatusOr<::google::iam::credentials::v1::SignJwtResponse> SignJwt(
      grpc::ClientContext& context,
      ::google::iam::credentials::v1::SignJwtRequest const& request) = 0;
};

class DefaultIAMCredentialsStub : public IAMCredentialsStub {
 public:
  explicit DefaultIAMCredentialsStub(
      std::unique_ptr<
          ::google::iam::credentials::v1::IAMCredentials::StubInterface>
          grpc_stub)
      : grpc_stub_(std::move(grpc_stub)) {}

  StatusOr<::google::iam::credentials::v1::GenerateAccessTokenResponse>
  GenerateAccessToken(
      grpc::ClientContext& client_context,
      ::google::iam::credentials::v1::GenerateAccessTokenRequest const& request)
      override;

  StatusOr<::google::iam::credentials::v1::GenerateIdTokenResponse>
  GenerateIdToken(grpc::ClientContext& client_context,
                  ::google::iam::credentials::v1::GenerateIdTokenRequest const&
                      request) override;

  StatusOr<::google::iam::credentials::v1::SignBlobResponse> SignBlob(
      grpc::ClientContext& client_context,
      ::google::iam::credentials::v1::SignBlobRequest const& request) override;

  StatusOr<::google::iam::credentials::v1::SignJwtResponse> SignJwt(
      grpc::ClientContext& client_context,
      ::google::iam::credentials::v1::SignJwtRequest const& request) override;

 private:
  std::unique_ptr<::google::iam::credentials::v1::IAMCredentials::StubInterface>
      grpc_stub_;
};

}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace iam_internal
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_IAM_INTERNAL_IAM_CREDENTIALS_STUB_GCPCXX_PB_H
