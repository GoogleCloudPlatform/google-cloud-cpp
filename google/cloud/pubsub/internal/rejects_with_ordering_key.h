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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_INTERNAL_REJECTS_WITH_ORDERING_KEY_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_INTERNAL_REJECTS_WITH_ORDERING_KEY_H

#include "google/cloud/pubsub/internal/message_batcher.h"
#include "google/cloud/pubsub/version.h"

namespace google {
namespace cloud {
namespace pubsub_internal {
inline namespace GOOGLE_CLOUD_CPP_PUBSUB_NS {

class RejectsWithOrderingKey : public MessageBatcher {
 public:
  static std::shared_ptr<RejectsWithOrderingKey> Create(
      std::shared_ptr<MessageBatcher> child) {
    return std::shared_ptr<RejectsWithOrderingKey>(
        new RejectsWithOrderingKey(std::move(child)));
  }

  ~RejectsWithOrderingKey() override = default;

  future<StatusOr<std::string>> Publish(pubsub::Message m) override;
  void Flush() override;
  void ResumePublish(std::string const&) override;

 private:
  explicit RejectsWithOrderingKey(std::shared_ptr<MessageBatcher> child)
      : child_(std::move(child)) {}

  std::shared_ptr<MessageBatcher> child_;
};

}  // namespace GOOGLE_CLOUD_CPP_PUBSUB_NS
}  // namespace pubsub_internal
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_PUBSUB_INTERNAL_REJECTS_WITH_ORDERING_KEY_H
