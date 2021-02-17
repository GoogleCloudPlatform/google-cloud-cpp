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

#include "google/cloud/internal/grpc_options.h"
#include "google/cloud/internal/absl_str_join_quiet.h"
#include "google/cloud/internal/common_options.h"

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {

namespace internal {

grpc::ChannelArguments MakeChannelArguments(Options const& opts) {
  grpc::ChannelArguments channel_arguments;
  auto const channel_args = opts.get<GrpcChannelArgumentsOption>();
  if (channel_args) {
    for (auto const& p : channel_args->value) {
      channel_arguments.SetString(p.first, p.second);
    }
  }
  auto const user_agent_prefix = opts.get<UserAgentPrefixOption>();
  if (user_agent_prefix) {
    channel_arguments.SetUserAgentPrefix(
        absl::StrJoin(user_agent_prefix->value, " "));
  }
  return channel_arguments;
}

}  // namespace internal

}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google
