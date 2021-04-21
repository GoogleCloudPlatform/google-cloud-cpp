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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_GRPC_CHANNEL_CREDENTIALS_AUTHENTICATION_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_GRPC_CHANNEL_CREDENTIALS_AUTHENTICATION_H

#include "google/cloud/internal/unified_grpc_credentials.h"
#include "google/cloud/version.h"
#include <grpcpp/grpcpp.h>

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {
namespace internal {

class GrpcChannelCredentialsAuthentication : public GrpcAuthenticationStrategy {
 public:
  explicit GrpcChannelCredentialsAuthentication(
      std::shared_ptr<grpc::ChannelCredentials> c)
      : credentials_(std::move(c)) {}
  ~GrpcChannelCredentialsAuthentication() override = default;

  std::shared_ptr<grpc::Channel> CreateChannel(
      std::string const& endpoint,
      grpc::ChannelArguments const& arguments) override;
  Status Setup(grpc::ClientContext&) override;

 private:
  std::shared_ptr<grpc::ChannelCredentials> credentials_;
};

}  // namespace internal
}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_GRPC_CHANNEL_CREDENTIALS_AUTHENTICATION_H
