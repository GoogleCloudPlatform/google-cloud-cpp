// Copyright 2020 Google LLC
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

#include "google/cloud/connection_options.h"
#include "google/cloud/internal/background_threads_impl.h"
#include "google/cloud/internal/compiler_info.h"
#include "google/cloud/log.h"
#include "google/cloud/testing_util/scoped_environment.h"
#include <gmock/gmock.h>
#include <map>

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {
namespace {

using ::testing::ElementsAre;
using ::testing::StartsWith;

/// Use these traits to test ConnectionOptions.
struct TestTraits {
  static std::string default_endpoint() { return "test-endpoint.example.com"; }
  static std::string user_agent_prefix() { return "test-prefix"; }
  static int default_num_channels() { return 7; }
};

using TestConnectionOptions = ConnectionOptions<TestTraits>;

TEST(ConnectionOptionsTest, Credentials) {
  // In the CI environment grpc::GoogleDefaultCredentials() may assert. Use the
  // insecure credentials to initialize the options in any unit test.
  auto expected = grpc::InsecureChannelCredentials();
  TestConnectionOptions options(expected);
  EXPECT_EQ(expected.get(), options.credentials().get());
  EXPECT_EQ(expected,
            internal::MakeOptions(options).get<GrpcCredentialOption>()->value);

  auto other_credentials = grpc::InsecureChannelCredentials();
  EXPECT_NE(expected, other_credentials);
  options.set_credentials(other_credentials);
  EXPECT_EQ(other_credentials, options.credentials());
  EXPECT_EQ(other_credentials, options.get<GrpcCredentialOption>()->value);
}

TEST(ConnectionOptionsTest, AdminEndpoint) {
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  EXPECT_EQ(TestTraits::default_endpoint(), options.endpoint());
  EXPECT_EQ(options.endpoint(), options.get<GrpcEndpointOption>()->value);

  options.set_endpoint("invalid-endpoint");
  EXPECT_EQ("invalid-endpoint", options.endpoint());
  EXPECT_EQ(options.endpoint(), options.get<GrpcEndpointOption>()->value);
}

TEST(ConnectionOptionsTest, NumChannels) {
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  int num_channels = options.num_channels();
  EXPECT_EQ(TestTraits::default_num_channels(), num_channels);
  EXPECT_EQ(options.num_channels(),
            options.get<GrpcNumChannelsOption>()->value);

  num_channels *= 2;  // ensure we change it from the default value.
  options.set_num_channels(num_channels);
  EXPECT_EQ(num_channels, options.num_channels());
  EXPECT_EQ(options.num_channels(),
            internal::MakeOptions(options).get<GrpcNumChannelsOption>()->value);
}

TEST(ConnectionOptionsTest, Tracing) {
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  options.enable_tracing("fake-component");
  EXPECT_TRUE(options.tracing_enabled("fake-component"));
  EXPECT_EQ(
      options.components(),
      internal::MakeOptions(options).get<GrpcTracingComponentsOption>()->value);

  options.disable_tracing("fake-component");
  EXPECT_FALSE(options.tracing_enabled("fake-component"));
  internal::MakeOptions(
      EXPECT_FALSE(options).get<GrpcTracingComponentsOption>());
}

TEST(ConnectionOptionsTest, DefaultTracingUnset) {
  testing_util::ScopedEnvironment env("GOOGLE_CLOUD_CPP_ENABLE_TRACING", {});
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  EXPECT_FALSE(options.tracing_enabled("rpc"));
  internal::MakeOptions(
      EXPECT_FALSE(options).get<GrpcTracingComponentsOption>());
}

TEST(ConnectionOptionsTest, DefaultTracingSet) {
  testing_util::ScopedEnvironment env("GOOGLE_CLOUD_CPP_ENABLE_TRACING",
                                      "foo,bar,baz");
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  EXPECT_FALSE(options.tracing_enabled("rpc"));
  EXPECT_TRUE(options.tracing_enabled("foo"));
  EXPECT_TRUE(options.tracing_enabled("bar"));
  EXPECT_TRUE(options.tracing_enabled("baz"));
  internal::MakeOptions(
      EXPECT_THAT(options).get<GrpcTracingComponentsOption>()->value,
      testing::UnorderedElementsAre("foo", "bar", "baz"));
}

TEST(ConnectionOptionsTest, TracingOptions) {
  testing_util::ScopedEnvironment env("GOOGLE_CLOUD_CPP_TRACING_OPTIONS",
                                      ",single_line_mode=off"
                                      ",use_short_repeated_primitives=off"
                                      ",truncate_string_field_longer_than=32");
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  TracingOptions tracing_options = options.tracing_options();
  EXPECT_FALSE(tracing_options.single_line_mode());
  EXPECT_FALSE(tracing_options.use_short_repeated_primitives());
  EXPECT_EQ(32, tracing_options.truncate_string_field_longer_than());
  EXPECT_EQ(
      options.tracing_options(),
      internal::MakeOptions(options).get<GrpcTracingOptionsOption>()->value);
}

TEST(ConnectionOptionsTest, ChannelPoolName) {
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  EXPECT_TRUE(options.channel_pool_domain().empty());
  internal::MakeOptions(
      EXPECT_FALSE(options).get<GrpcChannelArgumentsOption>());

  options.set_channel_pool_domain("test-channel-pool");
  EXPECT_EQ("test-channel-pool", options.channel_pool_domain());
  auto opts = internal::MakeOptions(options).get<GrpcChannelArgumentsOption>();
  EXPECT_TRUE(opts);
  EXPECT_EQ(opts->value[GRPC_ARG_CHANNEL_POOL_DOMAIN], "test-channel-pool");
}

TEST(ConnectionOptionsTest, UserAgentPrefix) {
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  EXPECT_EQ(TestTraits::user_agent_prefix(), options.user_agent_prefix());
  internal::MakeOptions(
      EXPECT_THAT(options).get<GrpcUserAgentPrefixOption>()->value,
      testing::ElementsAre(options.user_agent_prefix()));

  options.add_user_agent_prefix("test-prefix/1.2.3");
  EXPECT_EQ("test-prefix/1.2.3 " + TestTraits::user_agent_prefix(),
            options.user_agent_prefix());
  internal::MakeOptions(
      EXPECT_THAT(options).get<GrpcUserAgentPrefixOption>()->value,
      testing::ElementsAre(options.user_agent_prefix()));
}

TEST(ConnectionOptionsTest, CreateChannelArgumentsDefault) {
  TestConnectionOptions options(grpc::InsecureChannelCredentials());

  auto actual = options.CreateChannelArguments();

  // Use the low-level C API because grpc::ChannelArguments lacks high-level
  // accessors.
  grpc_channel_args test_args = actual.c_channel_args();
  ASSERT_EQ(1, test_args.num_args);
  ASSERT_EQ(GRPC_ARG_STRING, test_args.args[0].type);
  EXPECT_EQ("grpc.primary_user_agent", std::string(test_args.args[0].key));
  // The gRPC library adds its own version to the user-agent string, so we only
  // check that our component appears in it.
  EXPECT_THAT(std::string(test_args.args[0].value.string),
              StartsWith(options.user_agent_prefix()));
}

TEST(ConnectionOptionsTest, CreateChannelArgumentsWithChannelPool) {
  TestConnectionOptions options(grpc::InsecureChannelCredentials());
  options.set_channel_pool_domain("testing-pool");
  options.add_user_agent_prefix("test-prefix/1.2.3");

  auto actual = options.CreateChannelArguments();

  // Use the low-level C API because grpc::ChannelArguments lacks high-level
  // accessors.
  grpc_channel_args test_args = actual.c_channel_args();
  ASSERT_EQ(2, test_args.num_args);
  ASSERT_EQ(GRPC_ARG_STRING, test_args.args[0].type);
  ASSERT_EQ(GRPC_ARG_STRING, test_args.args[1].type);

  // There is no (AFAICT) guarantee on the order of the arguments in this array,
  // and the C types are hard to work with. Capture the arguments in a map to
  // make it easier to work with them.
  std::map<std::string, std::string> args;
  for (std::size_t i = 0; i != test_args.num_args; ++i) {
    args[test_args.args[i].key] = test_args.args[i].value.string;
  }

  EXPECT_EQ("testing-pool", args["grpc.channel_pooling_domain"]);
  // The gRPC library adds its own version to the user-agent string, so we only
  // check that our component appears in it.
  EXPECT_THAT(args["grpc.primary_user_agent"],
              StartsWith(options.user_agent_prefix()));
}

TEST(ConnectionOptionsTest, CustomBackgroundThreads) {
  CompletionQueue cq;

  auto options = TestConnectionOptions(grpc::InsecureChannelCredentials())
                     .DisableBackgroundThreads(cq);
  auto background = options.background_threads_factory()();

  using ms = std::chrono::milliseconds;

  // Schedule some work, it cannot execute because there is no thread attached.
  promise<std::thread::id> p;
  auto background_thread_id = p.get_future();
  background->cq().RunAsync(
      [&p](CompletionQueue&) { p.set_value(std::this_thread::get_id()); });
  EXPECT_NE(std::future_status::ready, background_thread_id.wait_for(ms(1)));

  // Verify we can create our own threads to drain the completion queue.
  std::thread t([&cq] { cq.Run(); });
  EXPECT_EQ(t.get_id(), background_thread_id.get());

  cq.Shutdown();
  t.join();
}

TEST(ConnectionOptionsTest, DefaultTracingComponentsNoEnvironment) {
  testing_util::ScopedEnvironment env("GOOGLE_CLOUD_CPP_ENABLE_TRACING", {});
  auto const actual = internal::DefaultTracingComponents();
  EXPECT_THAT(actual, ElementsAre());
}

TEST(ConnectionOptionsTest, DefaultTracingComponentsWithValue) {
  testing_util::ScopedEnvironment env("GOOGLE_CLOUD_CPP_ENABLE_TRACING",
                                      "a,b,c");
  auto const actual = internal::DefaultTracingComponents();
  EXPECT_THAT(actual, ElementsAre("a", "b", "c"));
}

TEST(ConnectionOptionsTest, DefaultTracingOptionsNoEnvironment) {
  testing_util::ScopedEnvironment env("GOOGLE_CLOUD_CPP_TRACING_OPTIONS", {});
  auto const actual = internal::DefaultTracingOptions();
  auto const expected = TracingOptions{};
  EXPECT_EQ(expected.single_line_mode(), actual.single_line_mode());
  EXPECT_EQ(expected.use_short_repeated_primitives(),
            actual.use_short_repeated_primitives());
  EXPECT_EQ(expected.truncate_string_field_longer_than(),
            actual.truncate_string_field_longer_than());
}

TEST(ConnectionOptionsTest, DefaultTracingOptionsWithValue) {
  testing_util::ScopedEnvironment env("GOOGLE_CLOUD_CPP_TRACING_OPTIONS",
                                      "single_line_mode=on"
                                      ",use_short_repeated_primitives=ON"
                                      ",truncate_string_field_longer_than=42");
  auto const actual = internal::DefaultTracingOptions();
  EXPECT_TRUE(actual.single_line_mode());
  EXPECT_TRUE(actual.use_short_repeated_primitives());
  EXPECT_EQ(42, actual.truncate_string_field_longer_than());
}

TEST(ConnectionOptionsTest, DefaultBackgroundThreads) {
  auto constexpr kThreadCount = 4;
  auto options = TestConnectionOptions(grpc::InsecureChannelCredentials())
                     .set_background_thread_pool_size(kThreadCount);
  auto background = options.background_threads_factory()();
  auto* tp = dynamic_cast<internal::AutomaticallyCreatedBackgroundThreads*>(
      background.get());
  ASSERT_NE(nullptr, tp);
  EXPECT_EQ(kThreadCount, tp->pool_size());
}

}  // namespace
}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google
