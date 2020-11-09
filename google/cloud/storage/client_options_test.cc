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

#include "google/cloud/storage/client_options.h"
#include "google/cloud/storage/oauth2/google_credentials.h"
#include "google/cloud/storage/testing/constants.h"
#include "google/cloud/internal/random.h"
#include "google/cloud/internal/setenv.h"
#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/testing_util/scoped_environment.h"
#include <gmock/gmock.h>
#include <cstdlib>
#include <fstream>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace {

using ::google::cloud::storage::testing::kJsonKeyfileContents;

class ClientOptionsTest : public ::testing::Test {
 public:
  ClientOptionsTest()
      : enable_tracing_("CLOUD_STORAGE_ENABLE_TRACING", {}),
        endpoint_("CLOUD_STORAGE_TESTBENCH_ENDPOINT", {}),
        generator_(std::random_device{}()) {}

  std::string CreateRandomFileName() {
    // When running on the internal Google CI systems we cannot write to the
    // local directory. GTest has a good temporary directory in that case.
    return ::testing::TempDir() +
           google::cloud::internal::Sample(
               generator_, 8, "abcdefghijklmnopqrstuvwxyz0123456789") +
           ".json";
  }

 protected:
  testing_util::ScopedEnvironment enable_tracing_;
  testing_util::ScopedEnvironment endpoint_;
  google::cloud::internal::DefaultPRNG generator_;
};

TEST_F(ClientOptionsTest, Default) {
  // Create the options with the anonymous credentials because the default
  // credentials try to load the application default credentials, and those do
  // not exist in the CI environment, which results in errors or warnings.
  auto creds = oauth2::CreateAnonymousCredentials();
  ClientOptions options(creds);
  EXPECT_FALSE(options.enable_http_tracing());
  EXPECT_FALSE(options.enable_raw_client_tracing());
  EXPECT_TRUE(creds.get() == options.credentials().get());
  EXPECT_EQ("https://storage.googleapis.com", options.endpoint());
  EXPECT_EQ("v1", options.version());
  EXPECT_EQ("https://iamcredentials.googleapis.com/v1", options.iam_endpoint());
}

TEST_F(ClientOptionsTest, CreateDefaultError) {
  testing_util::ScopedEnvironment creds("GOOGLE_APPLICATION_CREDENTIALS",
                                        "not-a-file-should-fail");
  auto connection = ClientOptions::CreateDefaultClientOptions();
  EXPECT_FALSE(connection.ok());
}

TEST_F(ClientOptionsTest, CreateDefaultWithChannelOptionsError) {
  testing_util::ScopedEnvironment creds("GOOGLE_APPLICATION_CREDENTIALS",
                                        "not-a-file-should-fail");
  auto connection = ClientOptions::CreateDefaultClientOptions({});
  EXPECT_FALSE(connection.ok());
}

TEST_F(ClientOptionsTest, CreateDefault) {
  auto file = CreateRandomFileName();
  std::ofstream(file) << kJsonKeyfileContents;
  testing_util::ScopedEnvironment creds("GOOGLE_APPLICATION_CREDENTIALS", file);
  auto connection = ClientOptions::CreateDefaultClientOptions();
  EXPECT_STATUS_OK(connection);
  std::remove(file.c_str());
}

TEST_F(ClientOptionsTest, CreateDefaultWithChannelOptions) {
  auto file = CreateRandomFileName();
  std::ofstream(file) << kJsonKeyfileContents;
  testing_util::ScopedEnvironment creds("GOOGLE_APPLICATION_CREDENTIALS", file);
  auto connection = ClientOptions::CreateDefaultClientOptions({});
  EXPECT_STATUS_OK(connection);
}

TEST_F(ClientOptionsTest, EnableRpc) {
  testing_util::ScopedEnvironment enable_tracing("CLOUD_STORAGE_ENABLE_TRACING",
                                                 "foo,raw-client,bar");
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  EXPECT_TRUE(options.enable_raw_client_tracing());
}

TEST_F(ClientOptionsTest, EnableHttp) {
  testing_util::ScopedEnvironment enable_tracing("CLOUD_STORAGE_ENABLE_TRACING",
                                                 "foo,http,bar");
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  EXPECT_TRUE(options.enable_http_tracing());
}

TEST_F(ClientOptionsTest, EndpointsDefault) {
  testing_util::ScopedEnvironment endpoint("CLOUD_STORAGE_TESTBENCH_ENDPOINT",
                                           {});
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  EXPECT_EQ("https://storage.googleapis.com", options.endpoint());
  EXPECT_EQ("https://storage.googleapis.com/storage/v1",
            internal::JsonEndpoint(options));
  EXPECT_EQ("https://storage.googleapis.com/upload/storage/v1",
            internal::JsonUploadEndpoint(options));
  EXPECT_EQ("https://iamcredentials.googleapis.com/v1",
            internal::IamEndpoint(options));
}

TEST_F(ClientOptionsTest, EndpointsOverride) {
  testing_util::ScopedEnvironment endpoint("CLOUD_STORAGE_TESTBENCH_ENDPOINT",
                                           {});
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  options.set_endpoint("http://127.0.0.1.nip.io:1234");
  EXPECT_EQ("http://127.0.0.1.nip.io:1234", options.endpoint());
  EXPECT_EQ("http://127.0.0.1.nip.io:1234/storage/v1",
            internal::JsonEndpoint(options));
  EXPECT_EQ("http://127.0.0.1.nip.io:1234/upload/storage/v1",
            internal::JsonUploadEndpoint(options));
  EXPECT_EQ("http://127.0.0.1.nip.io:1234", internal::XmlEndpoint(options));
  EXPECT_EQ("https://iamcredentials.googleapis.com/v1",
            internal::IamEndpoint(options));
}

TEST_F(ClientOptionsTest, EndpointsTestBench) {
  testing_util::ScopedEnvironment endpoint("CLOUD_STORAGE_TESTBENCH_ENDPOINT",
                                           "http://localhost:1234");
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  EXPECT_EQ("http://localhost:1234", options.endpoint());
  EXPECT_EQ("http://localhost:1234/storage/v1",
            internal::JsonEndpoint(options));
  EXPECT_EQ("http://localhost:1234/upload/storage/v1",
            internal::JsonUploadEndpoint(options));
  EXPECT_EQ("http://localhost:1234", internal::XmlEndpoint(options));
  EXPECT_EQ("http://localhost:1234/iamapi", internal::IamEndpoint(options));
}

TEST_F(ClientOptionsTest, SetVersion) {
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  options.set_version("vTest");
  EXPECT_EQ("vTest", options.version());
  EXPECT_EQ("https://storage.googleapis.com/storage/vTest",
            internal::JsonEndpoint(options));
  EXPECT_EQ("https://storage.googleapis.com/upload/storage/vTest",
            internal::JsonUploadEndpoint(options));
}

TEST_F(ClientOptionsTest, SetIamEndpoint) {
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  options.set_iam_endpoint("http://localhost:1/v2");
  EXPECT_EQ("http://localhost:1/v2", options.iam_endpoint());
}

TEST_F(ClientOptionsTest, SetCredentials) {
  auto creds = oauth2::CreateAnonymousCredentials();
  ClientOptions options(creds);
  auto other = oauth2::CreateAnonymousCredentials();
  options.set_credentials(other);
  EXPECT_TRUE(other.get() == options.credentials().get());
  EXPECT_FALSE(creds.get() == other.get());
}

TEST_F(ClientOptionsTest, ProjectIdFromEnvironment) {
  google::cloud::internal::SetEnv("GOOGLE_CLOUD_PROJECT", "test-project-id");
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  EXPECT_EQ("test-project-id", options.project_id());
}

TEST_F(ClientOptionsTest, ProjectIdFromEnvironmentNotSet) {
  google::cloud::internal::UnsetEnv("GOOGLE_CLOUD_PROJECT");
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  EXPECT_EQ("", options.project_id());
}

TEST_F(ClientOptionsTest, SetProjectId) {
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  options.set_project_id("test-project-id");
  EXPECT_EQ("test-project-id", options.project_id());
}

TEST_F(ClientOptionsTest, SetDownloadBufferSize) {
  ClientOptions client_options(oauth2::CreateAnonymousCredentials());
  auto default_size = client_options.download_buffer_size();
  EXPECT_NE(0U, default_size);
  client_options.SetDownloadBufferSize(1024);
  EXPECT_EQ(1024, client_options.download_buffer_size());
  client_options.SetDownloadBufferSize(0);
  EXPECT_EQ(default_size, client_options.download_buffer_size());
}

TEST_F(ClientOptionsTest, SetUploadBufferSize) {
  ClientOptions client_options(oauth2::CreateAnonymousCredentials());
  auto default_size = client_options.upload_buffer_size();
  EXPECT_NE(0U, default_size);
  client_options.SetUploadBufferSize(1024);
  EXPECT_EQ(1024, client_options.upload_buffer_size());
  client_options.SetUploadBufferSize(0);
  EXPECT_EQ(default_size, client_options.upload_buffer_size());
}

TEST_F(ClientOptionsTest, UserAgentPrefix) {
  ClientOptions options(oauth2::CreateAnonymousCredentials());
  EXPECT_EQ("", options.user_agent_prefix());
  options.add_user_agent_prefix("foo-1.0");
  EXPECT_EQ("foo-1.0", options.user_agent_prefix());
  options.add_user_agent_prefix("bar-2.2");
  EXPECT_EQ("bar-2.2/foo-1.0", options.user_agent_prefix());
}

TEST_F(ClientOptionsTest, SetMaximumSimpleUploadSize) {
  ClientOptions client_options(oauth2::CreateAnonymousCredentials());
  auto default_size = client_options.maximum_simple_upload_size();
  EXPECT_NE(0U, default_size);
  client_options.set_maximum_simple_upload_size(1024);
  EXPECT_EQ(1024, client_options.maximum_simple_upload_size());
  client_options.set_maximum_simple_upload_size(0);
  EXPECT_EQ(0, client_options.maximum_simple_upload_size());
}

TEST_F(ClientOptionsTest, SetEnableLockingCallbacks) {
  ClientOptions client_options(oauth2::CreateAnonymousCredentials());
  auto default_value = client_options.enable_ssl_locking_callbacks();
  EXPECT_TRUE(default_value);
  client_options.set_enable_ssl_locking_callbacks(false);
  EXPECT_FALSE(client_options.enable_ssl_locking_callbacks());
  client_options.set_enable_ssl_locking_callbacks(true);
  EXPECT_TRUE(client_options.enable_ssl_locking_callbacks());
}

TEST_F(ClientOptionsTest, SetMaximumSocketRecvSize) {
  ClientOptions client_options(oauth2::CreateAnonymousCredentials());
  auto default_value = client_options.maximum_socket_recv_size();
  EXPECT_EQ(0, default_value);
  client_options.set_maximum_socket_recv_size(16 * 1024);
  EXPECT_EQ(16 * 1024, client_options.maximum_socket_recv_size());
}

TEST_F(ClientOptionsTest, SetMaximumSocketSendSize) {
  ClientOptions client_options(oauth2::CreateAnonymousCredentials());
  auto default_value = client_options.maximum_socket_send_size();
  EXPECT_EQ(0, default_value);
  client_options.set_maximum_socket_send_size(16 * 1024);
  EXPECT_EQ(16 * 1024, client_options.maximum_socket_send_size());
}

TEST_F(ClientOptionsTest, SetMaximumDownloadStall) {
  ClientOptions client_options(oauth2::CreateAnonymousCredentials());
  auto default_value = client_options.download_stall_timeout();
  EXPECT_NE(0, default_value.count());
  client_options.set_download_stall_timeout(std::chrono::seconds(60));
  EXPECT_EQ(60, client_options.download_stall_timeout().count());
}

}  // namespace
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
