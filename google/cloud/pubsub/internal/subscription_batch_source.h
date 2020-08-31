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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_INTERNAL_SUBSCRIPTION_BATCH_SOURCE_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_INTERNAL_SUBSCRIPTION_BATCH_SOURCE_H

#include "google/cloud/pubsub/version.h"
#include "google/cloud/future.h"
#include "google/cloud/status.h"
#include "google/cloud/status_or.h"
#include <google/pubsub/v1/pubsub.pb.h>
#include <cstdint>
#include <string>
#include <vector>

namespace google {
namespace cloud {
namespace pubsub_internal {
inline namespace GOOGLE_CLOUD_CPP_PUBSUB_NS {

/**
 * Defines the interface for message batch sources.
 *
 * A message source generates messages via `BatchCallback` callbacks. Typically
 * messages are obtained by calling `AsyncPull()` on a `SubscriberStub`, but we
 * also need to mock this class in our tests and we implement message lease
 * management as a decorator.
 */
class SubscriptionBatchSource {
 public:
  virtual ~SubscriptionBatchSource() = default;

  /// Shutdown the source, cancel any outstanding requests and or timers. No
  /// callbacks should be generated after this call.
  virtual void Shutdown() = 0;

  /**
   * Positive acknowledgement the message associated with @p ack_id.
   *
   * The application has successfully handled this message and no new deliveries
   * are necessary. The @p size parameter should be the original message size
   * estimate. The @p size parameter may be used by the message source to flow
   * control large messages.
   */
  virtual future<Status> AckMessage(std::string const& ack_id,
                                    std::size_t size) = 0;

  /**
   * Negative acknowledgement for message associated with @p ack_id.
   *
   * The application has not able to handle this message. Nacking a message
   * allows the service to re-deliver it, subject to the topic and subscription
   * configuration. The @p size parameter should be the original message size
   * estimate. The @p size parameter may be used by the message source to flow
   * control large messages.
   */
  virtual future<Status> NackMessage(std::string const& ack_id,
                                     std::size_t size) = 0;

  /**
   * Negative acknowledgement of multiple messages.
   *
   * Typically generated by the application when shutting down a source.
   */
  virtual future<Status> BulkNack(std::vector<std::string> ack_ids,
                                  std::size_t total_size) = 0;

  /**
   * Request more messages from the source.
   */
  virtual future<StatusOr<google::pubsub::v1::PullResponse>> Pull(
      std::int32_t max_count) = 0;
};

}  // namespace GOOGLE_CLOUD_CPP_PUBSUB_NS
}  // namespace pubsub_internal
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_INTERNAL_SUBSCRIPTION_BATCH_SOURCE_H
