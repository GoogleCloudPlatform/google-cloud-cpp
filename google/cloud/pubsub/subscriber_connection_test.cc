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

#include "google/cloud/pubsub/subscriber_connection.h"
#include "google/cloud/pubsub/testing/mock_subscriber_stub.h"
#include "google/cloud/testing_util/assert_ok.h"
#include <gmock/gmock.h>

namespace google {
namespace cloud {
namespace pubsub {
inline namespace GOOGLE_CLOUD_CPP_PUBSUB_NS {
namespace {

using ::testing::_;

TEST(SubscriberConnectionTest, Basic) {
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();
  Subscription const subscription("test-project", "test-subscription");

  EXPECT_CALL(*mock, Pull(_, _))
      .Times(testing::AtLeast(1))
      .WillRepeatedly([&](grpc::ClientContext&,
                          google::pubsub::v1::PullRequest const& request) {
        EXPECT_EQ(subscription.FullName(), request.subscription());
        google::pubsub::v1::PullResponse response;
        auto& m = *response.add_received_messages();
        m.set_ack_id("test-ack-id-0");
        m.mutable_message()->set_message_id("test-message-id-0");
        return make_status_or(response);
      });
  EXPECT_CALL(*mock, Acknowledge(_, _))
      .Times(testing::AtLeast(1))
      .WillRepeatedly(
          [&](grpc::ClientContext&,
              google::pubsub::v1::AcknowledgeRequest const& request) {
            EXPECT_EQ(subscription.FullName(), request.subscription());
            EXPECT_FALSE(request.ack_ids().empty());
            for (auto& id : request.ack_ids()) {
              EXPECT_EQ("test-ack-id-0", id);
            }
            return Status{};
          });

  auto subscriber = pubsub_internal::MakeSubscriberConnection(mock);
  std::atomic_flag received_one{false};
  promise<void> waiter;
  auto handler = [&](Message const& m, AckHandler h) {
    EXPECT_EQ("test-message-id-0", m.message_id());
    EXPECT_STATUS_OK(std::move(h).ack());
    if (received_one.test_and_set()) return;
    waiter.set_value();
  };
  auto response = subscriber->Subscribe({subscription.FullName(), handler});
  waiter.get_future().wait();
  response.cancel();
  ASSERT_STATUS_OK(response.get());
}

TEST(SubscriberConnectionTest, PullFailure) {
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();
  Subscription const subscription("test-project", "test-subscription");

  auto const expected = Status(StatusCode::kPermissionDenied, "uh-oh");
  EXPECT_CALL(*mock, Pull(_, _))
      .Times(testing::AtLeast(1))
      .WillRepeatedly([&](grpc::ClientContext&,
                          google::pubsub::v1::PullRequest const& request) {
        EXPECT_EQ(subscription.FullName(), request.subscription());
        return StatusOr<google::pubsub::v1::PullResponse>(expected);
      });

  auto subscriber = pubsub_internal::MakeSubscriberConnection(mock);
  auto handler = [&](Message const&, AckHandler const&) {};
  auto response = subscriber->Subscribe({subscription.FullName(), handler});
  EXPECT_EQ(expected, response.get());
}

}  // namespace
}  // namespace GOOGLE_CLOUD_CPP_PUBSUB_NS
}  // namespace pubsub
}  // namespace cloud
}  // namespace google
