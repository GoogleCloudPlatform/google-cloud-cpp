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

#include "google/cloud/spanner/internal/defaults.h"
#include "google/cloud/spanner/internal/session_pool.h"
#include "google/cloud/spanner/options.h"
#include "google/cloud/spanner/session_pool_options.h"
#include "google/cloud/internal/common_options.h"
#include "google/cloud/internal/getenv.h"
#include "google/cloud/internal/grpc_options.h"
#include "google/cloud/internal/user_agent_prefix.h"
#include "google/cloud/options.h"
#include <chrono>
#include <string>

namespace google {
namespace cloud {
namespace spanner_internal {
inline namespace SPANNER_CLIENT_NS {

namespace {

// Sets basic defaults that apply to normal and admin connections.
void SetBasicDefaults(Options& opts) {
  if (!opts.has<internal::EndpointOption>()) {
    auto env = internal::GetEnv("GOOGLE_CLOUD_CPP_SPANNER_DEFAULT_ENDPOINT");
    opts.set<internal::EndpointOption>(env ? *env : "spanner.googleapis.com");
  }
  if (auto emulator = internal::GetEnv("SPANNER_EMULATOR_HOST")) {
    opts.set<internal::EndpointOption>(*emulator)
        .set<internal::GrpcCredentialOption>(
            grpc::InsecureChannelCredentials());
  }
  if (!opts.has<internal::GrpcCredentialOption>()) {
    opts.set<internal::GrpcCredentialOption>(grpc::GoogleDefaultCredentials());
  }
  if (!opts.has<internal::GrpcBackgroundThreadsFactoryOption>()) {
    opts.set<internal::GrpcBackgroundThreadsFactoryOption>(
        internal::DefaultBackgroundThreadsFactory);
  }
  if (!opts.has<internal::GrpcNumChannelsOption>()) {
    opts.set<internal::GrpcNumChannelsOption>(4);
  }
  // Inserts our user-agent string at the front.
  auto& products = opts.lookup<internal::UserAgentProductsOption>();
  products.insert(products.begin(), google::cloud::internal::UserAgentPrefix());
}

}  // namespace

Options DefaultOptions(Options opts) {
  SetBasicDefaults(opts);

  if (!opts.has<spanner_internal::SpannerRetryPolicyOption>()) {
    opts.set<spanner_internal::SpannerRetryPolicyOption>(
        std::make_shared<google::cloud::spanner::LimitedTimeRetryPolicy>(
            std::chrono::minutes(10)));
  }
  if (!opts.has<spanner_internal::SpannerBackoffPolicyOption>()) {
    auto constexpr kBackoffScaling = 2.0;
    opts.set<spanner_internal::SpannerBackoffPolicyOption>(
        std::make_shared<google::cloud::spanner::ExponentialBackoffPolicy>(
            std::chrono::milliseconds(100), std::chrono::minutes(1),
            kBackoffScaling));
  }

  // Sets Spanner-specific options from session_pool_options.h
  if (!opts.has<spanner_internal::SessionPoolMaxSessionsPerChannelOption>()) {
    opts.set<spanner_internal::SessionPoolMaxSessionsPerChannelOption>(100);
  }
  if (!opts.has<spanner_internal::SessionPoolActionOnExhaustionOption>()) {
    opts.set<spanner_internal::SessionPoolActionOnExhaustionOption>(
        spanner::ActionOnExhaustion::kBlock);
  }
  if (!opts.has<spanner_internal::SessionPoolKeepAliveIntervalOption>()) {
    opts.set<spanner_internal::SessionPoolKeepAliveIntervalOption>(
        std::chrono::minutes(55));
  }
  if (!opts.has<SessionPoolClockOption>()) {
    opts.set<SessionPoolClockOption>(std::make_shared<Session::Clock>());
  }
  // Enforces some SessionPool constraints.
  auto& max_idle =
      opts.lookup<spanner_internal::SessionPoolMaxIdleSessionsOption>();
  max_idle = (std::max)(max_idle, 0);
  auto& max_sessions_per_channel =
      opts.lookup<spanner_internal::SessionPoolMaxSessionsPerChannelOption>();
  max_sessions_per_channel = (std::max)(max_sessions_per_channel, 1);
  auto& min_sessions =
      opts.lookup<spanner_internal::SessionPoolMinSessionsOption>();
  min_sessions = (std::max)(min_sessions, 0);
  min_sessions =
      (std::min)(min_sessions, max_sessions_per_channel *
                                   opts.get<internal::GrpcNumChannelsOption>());

  return opts;
}

// Sets the options that have different defaults for admin connections, then
// uses `DefaultOptions()` to set all the remaining defaults.
Options DefaultAdminOptions(Options opts) {
  SetBasicDefaults(opts);

  if (!opts.has<spanner_internal::SpannerRetryPolicyOption>()) {
    opts.set<spanner_internal::SpannerRetryPolicyOption>(
        std::make_shared<google::cloud::spanner::LimitedTimeRetryPolicy>(
            std::chrono::minutes(30)));
  }
  if (!opts.has<spanner_internal::SpannerBackoffPolicyOption>()) {
    auto constexpr kBackoffScaling = 2.0;
    opts.set<spanner_internal::SpannerBackoffPolicyOption>(
        std::make_shared<google::cloud::spanner::ExponentialBackoffPolicy>(
            std::chrono::seconds(1), std::chrono::minutes(5), kBackoffScaling));
  }
  if (!opts.has<spanner_internal::SpannerPollingPolicyOption>()) {
    auto constexpr kBackoffScaling = 2.0;
    opts.set<spanner_internal::SpannerPollingPolicyOption>(
        std::make_shared<google::cloud::spanner::GenericPollingPolicy<>>(
            google::cloud::spanner::LimitedTimeRetryPolicy(
                std::chrono::minutes(30)),
            google::cloud::spanner::ExponentialBackoffPolicy(
                std::chrono::seconds(10), std::chrono::minutes(5),
                kBackoffScaling)));
  }

  return opts;
}

}  // namespace SPANNER_CLIENT_NS
}  // namespace spanner_internal
}  // namespace cloud
}  // namespace google
