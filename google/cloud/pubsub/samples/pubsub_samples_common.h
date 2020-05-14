// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_EXAMPLES_PUBSUB_EXAMPLES_COMMON_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_EXAMPLES_PUBSUB_EXAMPLES_COMMON_H

#include "google/cloud/pubsub/publisher_client.h"
#include "google/cloud/pubsub/subscriber_client.h"
#include "google/cloud/internal/example_driver.h"

namespace google {
namespace cloud {
namespace pubsub {
namespace examples {

using PublisherCommand = std::function<void(
    google::cloud::pubsub::PublisherClient, std::vector<std::string> const&)>;
using SubscriberCommand = std::function<void(
    google::cloud::pubsub::SubscriberClient, std::vector<std::string> const&)>;

google::cloud::internal::Commands::value_type CreatePublisherCommand(
    std::string const& name, std::vector<std::string> const& arg_names,
    PublisherCommand const& command);

google::cloud::internal::Commands::value_type CreateSubscriberCommand(
    std::string const& name, std::vector<std::string> const& arg_names,
    SubscriberCommand const& command);

}  // namespace examples
}  // namespace pubsub
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_EXAMPLES_PUBSUB_EXAMPLES_COMMON_H
