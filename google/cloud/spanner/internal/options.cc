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

#include "google/cloud/spanner/internal/options.h"
#include "google/cloud/internal/common_options.h"
#include "google/cloud/internal/compiler_info.h"
#include "google/cloud/internal/getenv.h"
#include "google/cloud/internal/grpc_options.h"
#include "google/cloud/internal/options.h"
#include <string>

namespace google {
namespace cloud {
namespace spanner_internal {
inline namespace SPANNER_CLIENT_NS {

internal::Options DefaultOptions(internal::Options opts) {
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
  if (opts.get<internal::GrpcNumChannelsOption>() < 1) {
    opts.set<internal::GrpcNumChannelsOption>(1);
  }
  // Inserts our user-agent string at the front.
  auto& products = opts.lookup<internal::UserAgentProductsOption>();
  products.insert(products.begin(),
                  "gcloud-cpp/" + google::cloud::spanner::VersionString() +
                      " (" + google::cloud::internal::CompilerId() + "-" +
                      google::cloud::internal::CompilerVersion() + "; " +
                      google::cloud::internal::CompilerFeatures() + ")");
  return opts;
}

}  // namespace SPANNER_CLIENT_NS
}  // namespace spanner_internal
}  // namespace cloud
}  // namespace google
