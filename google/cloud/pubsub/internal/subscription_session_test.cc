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

#include "google/cloud/pubsub/internal/subscription_session.h"
#include "google/cloud/pubsub/testing/mock_subscriber_stub.h"
#include "google/cloud/testing_util/assert_ok.h"
#include <gmock/gmock.h>
#include <atomic>

namespace google {
namespace cloud {
namespace pubsub_internal {
inline namespace GOOGLE_CLOUD_CPP_PUBSUB_NS {
namespace {

using ::testing::_;
using ::testing::AtLeast;
using ::testing::AtMost;

/// @test Verify callbacks are scheduled in the background threads.
TEST(SubscriptionSessionTest, ScheduleCallbacks) {
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();
  pubsub::Subscription const subscription("test-project", "test-subscription");

  std::mutex mu;
  int count = 0;
  EXPECT_CALL(*mock, AsyncPull(_, _, _))
      .Times(AtLeast(1))
      .WillRepeatedly([&](google::cloud::CompletionQueue&,
                          std::unique_ptr<grpc::ClientContext>,
                          google::pubsub::v1::PullRequest const& request) {
        EXPECT_EQ(subscription.FullName(), request.subscription());
        google::pubsub::v1::PullResponse response;
        for (int i = 0; i != 2; ++i) {
          auto& m = *response.add_received_messages();
          std::lock_guard<std::mutex> lk(mu);
          m.set_ack_id("test-ack-id-" + std::to_string(count));
          m.mutable_message()->set_message_id("test-message-id-" +
                                              std::to_string(count));
          ++count;
        }
        return make_ready_future(make_status_or(response));
      });

  std::atomic<int> expected_ack_id{0};
  EXPECT_CALL(*mock, AsyncAcknowledge(_, _, _))
      .Times(AtLeast(1))
      .WillRepeatedly(
          [&](google::cloud::CompletionQueue&,
              std::unique_ptr<grpc::ClientContext>,
              google::pubsub::v1::AcknowledgeRequest const& request) {
            EXPECT_EQ(subscription.FullName(), request.subscription());
            for (auto const& a : request.ack_ids()) {
              EXPECT_EQ("test-ack-id-" + std::to_string(expected_ack_id), a);
              ++expected_ack_id;
            }
            return make_ready_future(Status{});
          });

  google::cloud::CompletionQueue cq;
  std::vector<std::thread> tasks;
  std::generate_n(std::back_inserter(tasks), 4,
                  [&] { return std::thread([&cq] { cq.Run(); }); });
  std::set<std::thread::id> ids;
  auto const main_id = std::this_thread::get_id();
  std::transform(tasks.begin(), tasks.end(), std::inserter(ids, ids.end()),
                 [](std::thread const& t) { return t.get_id(); });

  std::atomic<int> expected_message_id{0};
  auto handler = [&](pubsub::Message const& m, pubsub::AckHandler h) {
    EXPECT_EQ("test-message-id-" + std::to_string(expected_message_id),
              m.message_id());
    auto pos = ids.find(std::this_thread::get_id());
    EXPECT_NE(ids.end(), pos);
    EXPECT_NE(main_id, std::this_thread::get_id());
    std::move(h).ack();
    ++expected_message_id;
  };

  auto session =
      SubscriptionSession::Create(mock, cq, {subscription.FullName(), handler});
  auto response = session->Start();
  while (expected_ack_id.load() < 100) {
    auto s = response.wait_for(std::chrono::milliseconds(5));
    if (s != std::future_status::timeout) break;
  }
  response.cancel();
  EXPECT_STATUS_OK(response.get());

  cq.Shutdown();
  for (auto& t : tasks) t.join();
}

/// @test Verify callbacks are scheduled in sequence.
TEST(SubscriptionSessionTest, SequencedCallbacks) {
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();
  pubsub::Subscription const subscription("test-project", "test-subscription");

  std::mutex mu;
  int count = 0;
  auto generate_3 = [&](google::cloud::CompletionQueue&,
                        std::unique_ptr<grpc::ClientContext>,
                        google::pubsub::v1::PullRequest const& request) {
    EXPECT_EQ(subscription.FullName(), request.subscription());
    google::pubsub::v1::PullResponse response;
    for (int i = 0; i != 3; ++i) {
      auto& m = *response.add_received_messages();
      std::lock_guard<std::mutex> lk(mu);
      m.set_ack_id("test-ack-id-" + std::to_string(count));
      m.mutable_message()->set_message_id("test-message-id-" +
                                          std::to_string(count));
      ++count;
    }
    return make_ready_future(make_status_or(response));
  };
  EXPECT_CALL(*mock, AsyncPull(_, _, _)).WillOnce(generate_3);

  // This receives a message, verify that it is the next message in the sequence
  // and then sets up the expectations for the next set of calls (mostly
  // AsyncPull).
  std::atomic<int> expected_message_id{0};
  auto handler = [&](pubsub::Message const& m, pubsub::AckHandler h) {
    SCOPED_TRACE("Running for message" + m.message_id());
    EXPECT_EQ("test-message-id-" + std::to_string(expected_message_id),
              m.message_id());
    auto ack_id = "test-ack-id-" + std::to_string(expected_message_id);
    EXPECT_CALL(*mock, AsyncAcknowledge(_, _, _))
        .WillOnce(
            [ack_id](google::cloud::CompletionQueue&,
                     std::unique_ptr<grpc::ClientContext>,
                     google::pubsub::v1::AcknowledgeRequest const& request) {
              for (auto const& a : request.ack_ids()) {
                EXPECT_EQ(ack_id, a);
              }
              return make_ready_future(Status{});
            });
    if (expected_message_id > 0 && expected_message_id % 3 == 2) {
      EXPECT_CALL(*mock, AsyncPull(_, _, _))
          .Times(AtMost(1))
          .WillRepeatedly(generate_3);
    }
    std::move(h).ack();
    ++expected_message_id;
  };

  google::cloud::CompletionQueue cq;
  std::thread t([&cq] { cq.Run(); });
  auto session =
      SubscriptionSession::Create(mock, cq, {subscription.FullName(), handler});
  auto response = session->Start();
  while (expected_message_id.load() < 50) {
    auto s = response.wait_for(std::chrono::milliseconds(5));
    if (s != std::future_status::timeout) break;
  }
  response.cancel();
  EXPECT_STATUS_OK(response.get());

  cq.Shutdown();
  t.join();
}

}  // namespace
}  // namespace GOOGLE_CLOUD_CPP_PUBSUB_NS
}  // namespace pubsub_internal
}  // namespace cloud
}  // namespace google
