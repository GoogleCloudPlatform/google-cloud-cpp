// Copyright 2018 Google Inc.
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

#include "bigtable/client/testing/embedded_server_test_fixture.h"
#include "bigtable/client/internal/throw_delegate.h"
#include <thread>

namespace bigtable {
namespace testing {

void EmbeddedServerTestFixture::StartServer() {
  int port;
  std::string server_address("[::]:0");
  builder_.AddListeningPort(server_address, grpc::InsecureServerCredentials(),
                            &port);
  builder_.RegisterService(&bigtable_service_);
  builder_.RegisterService(&admin_service_);
  server_ = builder_.BuildAndStart();
  address_ = "localhost:" + std::to_string(port);
  is_server_started_ = true;
  wait_thread_ = std::thread([this]() { server_->Wait(); });
}

void EmbeddedServerTestFixture::SetUp() {
  if (!is_server_started_) {
    StartServer();

    bigtable::ClientOptions options;
    options.set_admin_endpoint(address_);
    options.set_data_endpoint(address_);
    options.SetCredentials(grpc::InsecureChannelCredentials());

    grpc::ChannelArguments channel_arguments;
    static std::string const prefix = "cbt-c++/" + version_string();
    channel_arguments.SetUserAgentPrefix(prefix);

    std::shared_ptr<grpc::Channel> data_channel =
        server_->InProcessChannel(channel_arguments);
    data_client_ = std::make_shared<InProcessDtaClient>(
        std::move(kProjectId), std::move(kInstanceId), std::move(options),
        std::move(data_channel));
    table_ = std::make_shared<bigtable::Table>(data_client_, kTableId);

    std::shared_ptr<grpc::Channel> admin_channel =
        server_->InProcessChannel(channel_arguments);
    admin_client_ = std::make_shared<InProcessAdminClient>(
        std::move(kProjectId), std::move(options), std::move(admin_channel));
    admin_ = std::make_shared<bigtable::TableAdmin>(admin_client_, kInstanceId);
  }
}

void EmbeddedServerTestFixture::TearDown() {
  if (is_server_started_) {
    server_->Shutdown();
    wait_thread_.join();
  }
}

}  // namespace testing
}  // namespace bigtable
