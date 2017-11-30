// Copyright 2017 Google Inc.
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

#ifndef BIGTABLE_CLIENT_CLIENTOPTIONS_H_
#define BIGTABLE_CLIENT_CLIENTOPTIONS_H_

#include <grpc++/grpc++.h>

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Configuration options for the Bigtable Client.
 *
 * Applications typically configure the client class using:
 * @code
 * auto client =
 * bigtable::Client(bigtable::ClientOptions().SetCredentials(...));
 * @endcode
 */
class ClientOptions {
 public:
  ClientOptions();
  const std::string& endpoint() const { return endpoint_; }
  ClientOptions& SetEndpoint(const std::string& endpoint) {
    endpoint_ = endpoint;
    return *this;
  }
  std::shared_ptr<grpc::ChannelCredentials> credentials() const {
    return credentials_;
  }
  ClientOptions& SetCredentials(
      std::shared_ptr<grpc::ChannelCredentials> credentials) {
    credentials_ = credentials;
    return *this;
  }
  // TODO() create setter/getter for each channel argument. Issue #53
  const grpc::ChannelArguments channel_arguments() const {
    return channel_arguments_;
  }
  ClientOptions& SetChannelArguments(grpc::ChannelArguments channel_arguments) {
    channel_arguments_ = channel_arguments;
    return *this;
  }

 private:
  // Endpoint here stands for data endpoint for fetching data.
  std::string endpoint_;
  std::shared_ptr<grpc::ChannelCredentials> credentials_;
  grpc::ChannelArguments channel_arguments_;
};
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // BIGTABLE_CLIENT_CLIENTOPTIONS_H_
