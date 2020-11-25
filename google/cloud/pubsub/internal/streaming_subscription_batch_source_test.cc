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

#include "google/cloud/pubsub/internal/streaming_subscription_batch_source.h"
#include "google/cloud/pubsub/subscription.h"
#include "google/cloud/pubsub/testing/mock_subscriber_stub.h"
#include "google/cloud/pubsub/testing/test_retry_policies.h"
#include "google/cloud/internal/background_threads_impl.h"
#include "google/cloud/log.h"
#include "google/cloud/testing_util/async_sequencer.h"
#include "google/cloud/testing_util/capture_log_lines_backend.h"
#include "google/cloud/testing_util/mock_completion_queue_impl.h"
#include "google/cloud/testing_util/status_matchers.h"
#include <gmock/gmock.h>
#include <deque>
#include <sstream>

namespace google {
namespace cloud {
namespace pubsub_internal {
inline namespace GOOGLE_CLOUD_CPP_PUBSUB_NS {
namespace {

using ::google::cloud::internal::AutomaticallyCreatedBackgroundThreads;
using ::google::cloud::pubsub_testing::TestBackoffPolicy;
using ::google::cloud::pubsub_testing::TestRetryPolicy;
using ::google::cloud::testing_util::AsyncSequencer;
using ::google::cloud::testing_util::StatusIs;
using ::testing::_;
using ::testing::AtLeast;
using ::testing::AtMost;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::MockFunction;
using ::testing::Property;
using ::testing::UnorderedElementsAre;
using ::testing::Unused;

class FakeStream {
 public:
  explicit FakeStream(Status finish) : finish_(std::move(finish)) {}

  promise<bool> WaitForAction() {
    auto p = async_.PopFrontWithName();
    GCP_LOG(DEBUG) << __func__ << "(" << p.second << ")";
    return std::move(p.first);
  }

  std::unique_ptr<pubsub_testing::MockAsyncPullStream> MakeWriteFailureStream(
      google::cloud::CompletionQueue&, std::unique_ptr<grpc::ClientContext>,
      google::pubsub::v1::StreamingPullRequest const&) {
    auto start_response = [this] {
      return AddAction("Start").then([](future<bool> g) { return g.get(); });
    };
    auto write_response = [this](
                              google::pubsub::v1::StreamingPullRequest const&,
                              grpc::WriteOptions const&) {
      return AddAction("Write").then([](future<bool> g) { return g.get(); });
    };
    auto read_response = [this] {
      return AddAction("Read").then([](future<bool> g) {
        auto ok = g.get();
        using Response = google::pubsub::v1::StreamingPullResponse;
        if (!ok) return absl::optional<Response>{};
        return absl::make_optional(Response{});
      });
    };
    auto finish_response = [this] {
      auto s = finish_;
      return AddAction("Finish").then(
          [s](future<bool>) mutable { return std::move(s); });
    };

    auto stream = absl::make_unique<pubsub_testing::MockAsyncPullStream>();
    EXPECT_CALL(*stream, Start).WillOnce(start_response);
    EXPECT_CALL(*stream, Write).WillRepeatedly(write_response);
    EXPECT_CALL(*stream, Cancel).Times(AtMost(1));
    EXPECT_CALL(*stream, Read).WillRepeatedly(read_response);
    EXPECT_CALL(*stream, Finish).WillOnce(finish_response);

    return stream;
  }

  future<bool> AddAction(char const* caller) {
    GCP_LOG(DEBUG) << __func__ << "(" << caller << ")";
    return async_.PushBack(caller);
  }

 private:
  Status finish_;
  AsyncSequencer<bool> async_;
};

pubsub::SubscriberOptions TestSubscriptionOptions() {
  return pubsub::SubscriberOptions()
      .set_max_outstanding_messages(100)
      .set_max_outstanding_bytes(100 * 1024 * 1024L)
      .set_max_deadline_time(std::chrono::seconds(300));
}

AckBatchingConfig TestBatchingConfig() {
  return AckBatchingConfig(1, std::chrono::milliseconds(10));
}

TEST(StreamingSubscriptionBatchSourceTest, Start) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  FakeStream success_stream(Status{});

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue& cq,
                    std::unique_ptr<grpc::ClientContext> context,
                    google::pubsub::v1::StreamingPullRequest const& request) {
        return success_stream.MakeWriteFailureStream(cq, std::move(context),
                                                     request);
      });

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start([](StatusOr<google::pubsub::v1::StreamingPullResponse> const&) {});
  success_stream.WaitForAction().set_value(true);  // Start()
  success_stream.WaitForAction().set_value(true);  // Write()
  success_stream.WaitForAction().set_value(true);  // Read()
  auto last = success_stream.WaitForAction();      // Read()
  shutdown->MarkAsShutdown("test", {});
  uut->Shutdown();
  last.set_value(false);
  success_stream.WaitForAction().set_value(true);  // Finish()

  EXPECT_THAT(done.get(), StatusIs(StatusCode::kOk));
}

TEST(StreamingSubscriptionBatchSourceTest, StartWithRetry) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  auto const transient = Status{StatusCode::kUnavailable, "try-again"};
  FakeStream start_failure(transient);
  FakeStream write_failure(transient);
  FakeStream success_stream(Status{});

  auto make_async_pull_mock = [](FakeStream& fake) {
    return [&fake](google::cloud::CompletionQueue& cq,
                   std::unique_ptr<grpc::ClientContext> context,
                   google::pubsub::v1::StreamingPullRequest const& request) {
      return fake.MakeWriteFailureStream(cq, std::move(context), request);
    };
  };

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce(make_async_pull_mock(start_failure))
      .WillOnce(make_async_pull_mock(write_failure))
      .WillOnce(make_async_pull_mock(success_stream));

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy());

  auto done = shutdown->Start({});
  uut->Start([](StatusOr<google::pubsub::v1::StreamingPullResponse> const&) {});

  start_failure.WaitForAction().set_value(false);  // Start()
  start_failure.WaitForAction().set_value(true);   // Finish()

  write_failure.WaitForAction().set_value(true);   // Start()
  write_failure.WaitForAction().set_value(false);  // Write()
  write_failure.WaitForAction().set_value(true);   // Finish()

  success_stream.WaitForAction().set_value(true);  // Start()
  success_stream.WaitForAction().set_value(true);  // Write()
  success_stream.WaitForAction().set_value(true);  // Read()
  auto last = success_stream.WaitForAction();
  shutdown->MarkAsShutdown("test", {});
  uut->Shutdown();
  last.set_value(false);
  success_stream.WaitForAction().set_value(true);  // Finish()

  EXPECT_THAT(done.get(), StatusIs(StatusCode::kOk));
}

TEST(StreamingSubscriptionBatchSourceTest, StartTooManyTransientFailures) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  auto const transient = Status{StatusCode::kUnavailable, "try-again"};

  auto async_pull_mock = [transient](
                             google::cloud::CompletionQueue& cq,
                             std::unique_ptr<grpc::ClientContext>,
                             google::pubsub::v1::StreamingPullRequest const&) {
    using us = std::chrono::microseconds;
    using F = future<StatusOr<std::chrono::system_clock::time_point>>;
    using Response = google::pubsub::v1::StreamingPullResponse;
    auto start_response = [cq]() mutable {
      return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
    };
    auto write_response = [cq](google::pubsub::v1::StreamingPullRequest const&,
                               grpc::WriteOptions const&) mutable {
      return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
    };
    auto read_response = [cq]() mutable {
      return cq.MakeRelativeTimer(us(10)).then(
          [](F) { return absl::optional<Response>{}; });
    };
    auto finish_response = [cq, transient]() mutable {
      return cq.MakeRelativeTimer(us(10)).then(
          // NOLINTNEXTLINE(performance-no-automatic-move)
          [transient](F) { return transient; });
    };

    auto stream = absl::make_unique<pubsub_testing::MockAsyncPullStream>();
    EXPECT_CALL(*stream, Start).WillOnce(start_response);
    EXPECT_CALL(*stream, Write).WillRepeatedly(write_response);
    EXPECT_CALL(*stream, Cancel).Times(AtMost(1));
    EXPECT_CALL(*stream, Read).WillRepeatedly(read_response);
    EXPECT_CALL(*stream, Finish).WillOnce(finish_response);

    return stream;
  };

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .Times(AtLeast(2))
      .WillRepeatedly(async_pull_mock);

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  promise<Status> p;
  uut->Start([&](StatusOr<google::pubsub::v1::StreamingPullResponse> r) {
    p.set_value(std::move(r).status());
  });
  auto const status = p.get_future().get();
  EXPECT_THAT(status,
              StatusIs(transient.code(), HasSubstr(transient.message())));
  uut->Shutdown();

  EXPECT_EQ(done.get(), status);
}

TEST(StreamingSubscriptionBatchSourceTest, StartWithIgnoredUnavailable) {
  using Response = google::pubsub::v1::StreamingPullResponse;

  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  AsyncSequencer<Status> on_finish;
  auto async_pull_mock = [&on_finish](
                             google::cloud::CompletionQueue& cq,
                             std::unique_ptr<grpc::ClientContext>,
                             google::pubsub::v1::StreamingPullRequest const&) {
    using us = std::chrono::microseconds;
    using F = future<StatusOr<std::chrono::system_clock::time_point>>;
    auto start_response = [cq]() mutable {
      return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
    };
    auto write_response = [cq](google::pubsub::v1::StreamingPullRequest const&,
                               grpc::WriteOptions const&) mutable {
      return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
    };
    auto read_response = [cq]() mutable {
      return cq.MakeRelativeTimer(us(10)).then(
          [](F) { return absl::optional<Response>{}; });
    };
    auto finish_response = [&on_finish]() mutable {
      return on_finish.PushBack("Finish").then(
          [](future<Status> f) { return f.get(); });
    };

    auto stream = absl::make_unique<pubsub_testing::MockAsyncPullStream>();
    EXPECT_CALL(*stream, Start).WillOnce(start_response);
    EXPECT_CALL(*stream, Write).WillRepeatedly(write_response);
    EXPECT_CALL(*stream, Cancel).Times(AtMost(1));
    EXPECT_CALL(*stream, Read).WillRepeatedly(read_response);
    EXPECT_CALL(*stream, Finish).WillOnce(finish_response);

    return stream;
  };
  EXPECT_CALL(*mock, AsyncStreamingPull)
      .Times(AtLeast(2))
      .WillRepeatedly(async_pull_mock);

  ::testing::MockFunction<void(StatusOr<Response>)> callback;
  EXPECT_CALL(callback, Call(StatusIs(StatusCode::kPermissionDenied)));

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start(callback.AsStdFunction());

  for (int i = 0; i != 4; ++i) {
    on_finish.PopFront().set_value(
        Status(StatusCode::kUnavailable,
               "The service was unable to fulfill your request."
               " Please try again. [code=8a75]"));
  }
  auto const final_status = Status(StatusCode::kPermissionDenied, "uh-oh");
  on_finish.PopFront().set_value(final_status);
  uut->Shutdown();

  EXPECT_EQ(done.get(), final_status);
}

TEST(StreamingSubscriptionBatchSourceTest, StartPermanentFailure) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  auto const transient = Status{StatusCode::kPermissionDenied, "uh-oh"};

  auto async_pull_mock = [transient](
                             google::cloud::CompletionQueue& cq,
                             std::unique_ptr<grpc::ClientContext>,
                             google::pubsub::v1::StreamingPullRequest const&) {
    using us = std::chrono::microseconds;
    using F = future<StatusOr<std::chrono::system_clock::time_point>>;
    using Response = google::pubsub::v1::StreamingPullResponse;
    auto start_response = [cq]() mutable {
      return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
    };
    auto write_response = [cq](google::pubsub::v1::StreamingPullRequest const&,
                               grpc::WriteOptions const&) mutable {
      return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
    };
    auto read_response = [cq]() mutable {
      return cq.MakeRelativeTimer(us(10)).then(
          [](F) { return absl::optional<Response>{}; });
    };
    auto finish_response = [cq, transient]() mutable {
      return cq.MakeRelativeTimer(us(10)).then(
          // NOLINTNEXTLINE(performance-no-automatic-move)
          [transient](F) { return transient; });
    };

    auto stream = absl::make_unique<pubsub_testing::MockAsyncPullStream>();
    EXPECT_CALL(*stream, Start).WillOnce(start_response);
    EXPECT_CALL(*stream, Write).WillRepeatedly(write_response);
    EXPECT_CALL(*stream, Cancel).Times(AtMost(1));
    EXPECT_CALL(*stream, Read).WillRepeatedly(read_response);
    EXPECT_CALL(*stream, Finish).WillOnce(finish_response);

    return stream;
  };

  EXPECT_CALL(*mock, AsyncStreamingPull).WillOnce(async_pull_mock);

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  promise<Status> p;
  uut->Start([&](StatusOr<google::pubsub::v1::StreamingPullResponse> r) {
    p.set_value(std::move(r).status());
  });
  auto const status = p.get_future().get();
  EXPECT_THAT(status,
              StatusIs(transient.code(), HasSubstr(transient.message())));
  uut->Shutdown();

  EXPECT_EQ(done.get(), status);
}

TEST(StreamingSubscriptionBatchSourceTest, StartUnexpected) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .Times(1)
      .WillRepeatedly([](google::cloud::CompletionQueue&,
                         std::unique_ptr<grpc::ClientContext>,
                         google::pubsub::v1::StreamingPullRequest const&) {
        return std::unique_ptr<SubscriberStub::AsyncPullStream>{};
      });

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  promise<Status> p;
  uut->Start([&](StatusOr<google::pubsub::v1::StreamingPullResponse> r) {
    p.set_value(std::move(r).status());
  });
  auto status = p.get_future().get();
  EXPECT_THAT(status, StatusIs(StatusCode::kUnknown));
  uut->Shutdown();

  EXPECT_EQ(done.get(), status);
}

TEST(StreamingSubscriptionBatchSourceTest, StartSucceedsAfterShutdown) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  FakeStream success_stream(Status{StatusCode::kCancelled, "cancelled"});

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue& cq,
                    std::unique_ptr<grpc::ClientContext> context,
                    google::pubsub::v1::StreamingPullRequest const& request) {
        return success_stream.MakeWriteFailureStream(cq, std::move(context),
                                                     request);
      });

  using CallbackArg = StatusOr<google::pubsub::v1::StreamingPullResponse>;
  ::testing::MockFunction<void(CallbackArg const&)> callback;
  EXPECT_CALL(callback, Call).Times(0);

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start(callback.AsStdFunction());
  success_stream.WaitForAction().set_value(true);  // Start()
  success_stream.WaitForAction().set_value(true);  // Write()
  shutdown->MarkAsShutdown("test", {});
  success_stream.WaitForAction().set_value(true);  // Read()
  success_stream.WaitForAction().set_value(true);  // Finish()

  EXPECT_EQ(Status{}, done.get());
}

TEST(StreamingSubscriptionBatchSourceTest, ResumeAfterFirstRead) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  auto make_async_pull_mock = [](int start, int count) {
    return [start, count](google::cloud::CompletionQueue& cq,
                          std::unique_ptr<grpc::ClientContext>,
                          google::pubsub::v1::StreamingPullRequest const&) {
      using us = std::chrono::microseconds;
      using F = future<StatusOr<std::chrono::system_clock::time_point>>;
      using Response = google::pubsub::v1::StreamingPullResponse;
      auto start_response = [cq]() mutable {
        return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
      };
      auto write_response = [cq](
                                google::pubsub::v1::StreamingPullRequest const&,
                                grpc::WriteOptions const&) mutable {
        return cq.MakeRelativeTimer(us(10)).then([](F) { return true; });
      };
      auto read_success = [cq, start, count]() mutable {
        return cq.MakeRelativeTimer(us(10)).then([start, count](F) {
          Response response;
          for (int i = 0; i != count; ++i) {
            response.add_received_messages()->set_ack_id(
                "ack-" + std::to_string(start + i));
          }
          return absl::make_optional(std::move(response));
        });
      };
      auto read_failure = [cq]() mutable {
        return cq.MakeRelativeTimer(us(10)).then(
            [](F) { return absl::optional<Response>{}; });
      };
      auto finish_response = [cq]() mutable {
        return cq.MakeRelativeTimer(us(10)).then([](F) mutable {
          return Status{StatusCode::kUnavailable, "try-again"};
        });
      };

      auto stream = absl::make_unique<pubsub_testing::MockAsyncPullStream>();
      EXPECT_CALL(*stream, Start).WillOnce(start_response);
      EXPECT_CALL(*stream, Write).WillRepeatedly(write_response);
      EXPECT_CALL(*stream, Cancel).Times(AtMost(1));
      EXPECT_CALL(*stream, Read).WillOnce(read_success).WillOnce(read_failure);
      EXPECT_CALL(*stream, Finish).WillOnce(finish_response);

      return stream;
    };
  };

  promise<void> ready;
  promise<void> wait;
  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce(make_async_pull_mock(0, 3))
      .WillOnce(make_async_pull_mock(3, 2))
      .WillOnce([&](google::cloud::CompletionQueue&,
                    std::unique_ptr<grpc::ClientContext>,
                    google::pubsub::v1::StreamingPullRequest const&) {
        ready.set_value();
        wait.get_future().wait();
        return nullptr;
      });

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  std::vector<std::string> ids;
  uut->Start([&](StatusOr<google::pubsub::v1::StreamingPullResponse> r) {
    if (!r) return;
    for (auto const& m : r->received_messages()) ids.push_back(m.ack_id());
  });
  ready.get_future().wait();
  shutdown->MarkAsShutdown("test", {});
  wait.set_value();
  EXPECT_EQ(done.get(), Status{});
  EXPECT_THAT(ids, ElementsAre("ack-0", "ack-1", "ack-2", "ack-3", "ack-4"));
}

TEST(StreamingSubscriptionBatchSourceTest, AckMany) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  FakeStream success_stream(Status{});

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue& cq,
                    std::unique_ptr<grpc::ClientContext> context,
                    google::pubsub::v1::StreamingPullRequest const& request) {
        auto stream = success_stream.MakeWriteFailureStream(
            cq, std::move(context), request);
        using Request = google::pubsub::v1::StreamingPullRequest;
        // Add expectations for Write() calls with empty subscriptions, only
        // the first call has a non-empty value and it is already set.
        EXPECT_CALL(*stream,
                    Write(Property(&Request::subscription, std::string{}), _))
            .WillOnce(
                [&](google::pubsub::v1::StreamingPullRequest const& request,
                    grpc::WriteOptions const& options) {
                  EXPECT_THAT(request.ack_ids(), ElementsAre("fake-001"));
                  EXPECT_THAT(request.modify_deadline_ack_ids(), IsEmpty());
                  EXPECT_THAT(request.modify_deadline_seconds(), IsEmpty());
                  EXPECT_THAT(request.client_id(), IsEmpty());
                  EXPECT_THAT(request.subscription(), IsEmpty());
                  EXPECT_TRUE(options.is_write_through());
                  return success_stream.AddAction("Write");
                })
            .WillOnce(
                [&](google::pubsub::v1::StreamingPullRequest const& request,
                    grpc::WriteOptions const& options) {
                  EXPECT_THAT(request.ack_ids(), ElementsAre("fake-002"));
                  EXPECT_THAT(request.modify_deadline_ack_ids(),
                              ElementsAre("fake-003"));
                  EXPECT_THAT(request.modify_deadline_seconds(),
                              ElementsAre(0));
                  EXPECT_THAT(request.client_id(), IsEmpty());
                  EXPECT_THAT(request.subscription(), IsEmpty());
                  EXPECT_TRUE(options.is_write_through());
                  return success_stream.AddAction("Write");
                })
            .WillOnce(
                [&](google::pubsub::v1::StreamingPullRequest const& request,
                    grpc::WriteOptions const&) {
                  EXPECT_THAT(request.modify_deadline_ack_ids(),
                              ElementsAre("fake-004", "fake-005"));
                  EXPECT_THAT(request.modify_deadline_seconds(),
                              ElementsAre(0, 0));
                  EXPECT_THAT(request.ack_ids(), IsEmpty());
                  EXPECT_THAT(request.client_id(), IsEmpty());
                  EXPECT_THAT(request.subscription(), IsEmpty());
                  return success_stream.AddAction("Write");
                });
        return stream;
      });

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start([](StatusOr<google::pubsub::v1::StreamingPullResponse> const&) {});
  success_stream.WaitForAction().set_value(true);  // Start()
  success_stream.WaitForAction().set_value(true);  // Write()
  success_stream.WaitForAction().set_value(true);  // Read()
  auto last_read = success_stream.WaitForAction();

  uut->AckMessage("fake-001");
  uut->AckMessage("fake-002");
  uut->NackMessage("fake-003");
  // Flush the first AckMessage()
  success_stream.WaitForAction().set_value(true);  // Write()
  // Flush the compiled AckMessage() + NackMessage()
  success_stream.WaitForAction().set_value(true);  // Write()

  uut->BulkNack({"fake-004", "fake-005"});
  success_stream.WaitForAction().set_value(true);  // Write()

  shutdown->MarkAsShutdown("test", {});
  uut->Shutdown();
  last_read.set_value(false);                      // Read()
  success_stream.WaitForAction().set_value(true);  // Finish()

  EXPECT_THAT(done.get(), StatusIs(StatusCode::kOk));
}

TEST(StreamingSubscriptionBatchSourceTest, AckBatching) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";

  // We will configure StreamingSubscriptionBatchSource's to use this period
  // in its periodic timer.
  auto constexpr kHz = std::chrono::milliseconds(42);

  // How often do we flush the buffers.
  auto constexpr kAckHz = std::chrono::milliseconds(250);

  // We mock the wall clock by changing this variable, we start with an easy
  // to recognize value.
  auto start = std::chrono::system_clock::time_point{} +
               std::chrono::seconds(1000000000ULL);
  std::chrono::system_clock::time_point mocked_now = start;
  MockFunction<std::chrono::system_clock::time_point()> mock_clock;
  EXPECT_CALL(mock_clock, Call).WillRepeatedly([&] { return mocked_now; });

  AsyncSequencer<void> async;
  AsyncSequencer<void> timer;
  auto mock_cq =
      std::make_shared<google::cloud::testing_util::MockCompletionQueueImpl>();
  EXPECT_CALL(*mock_cq, MakeRelativeTimer)
      .WillRepeatedly([&](std::chrono::nanoseconds d) {
        EXPECT_EQ(d, kHz);
        auto deadline = mocked_now + d;
        return timer.PushBack().then(
            [deadline](future<void>) { return make_status_or(deadline); });
      });
  EXPECT_CALL(*mock_cq, RunAsync)
      .WillRepeatedly([&async](std::unique_ptr<internal::RunAsyncBase> f) {
        struct MoveCapture {
          std::unique_ptr<internal::RunAsyncBase> function;
          void operator()(future<void>) const { function->exec(); }
        };
        return async.PushBack().then(MoveCapture{std::move(f)});
      });

  FakeStream success_stream(Status{});
  auto constexpr kBatchSize = 10;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();
  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue& cq,
                    std::unique_ptr<grpc::ClientContext> context,
                    google::pubsub::v1::StreamingPullRequest const& request) {
        auto stream = success_stream.MakeWriteFailureStream(
            cq, std::move(context), request);
        using Request = google::pubsub::v1::StreamingPullRequest;
        // Add expectations for Write() calls with empty subscriptions, only
        // the first call has a non-empty value and it is already set.
        EXPECT_CALL(*stream,
                    Write(Property(&Request::subscription, std::string{}), _))
            .WillOnce(
                [&](Request const& request, grpc::WriteOptions const& options) {
                  EXPECT_EQ(kBatchSize, request.ack_ids_size());
                  EXPECT_THAT(request.modify_deadline_ack_ids(), IsEmpty());
                  EXPECT_THAT(request.modify_deadline_seconds(), IsEmpty());
                  EXPECT_THAT(request.client_id(), IsEmpty());
                  EXPECT_THAT(request.subscription(), IsEmpty());
                  EXPECT_TRUE(options.is_write_through());
                  return success_stream.AddAction("Write/1");
                })
            .WillOnce(
                [&](Request const& request, grpc::WriteOptions const& options) {
                  EXPECT_THAT(request.ack_ids(), IsEmpty());
                  EXPECT_EQ(kBatchSize, request.modify_deadline_ack_ids_size());
                  EXPECT_EQ(kBatchSize, request.modify_deadline_seconds_size());
                  EXPECT_THAT(request.client_id(), IsEmpty());
                  EXPECT_THAT(request.subscription(), IsEmpty());
                  EXPECT_TRUE(options.is_write_through());
                  return success_stream.AddAction("Write/2");
                })
            .WillOnce(
                [&](Request const& request, grpc::WriteOptions const& options) {
                  EXPECT_EQ(kBatchSize / 2, request.ack_ids_size());
                  EXPECT_THAT(request.modify_deadline_ack_ids(), IsEmpty());
                  EXPECT_THAT(request.modify_deadline_seconds(), IsEmpty());
                  EXPECT_THAT(request.client_id(), IsEmpty());
                  EXPECT_THAT(request.subscription(), IsEmpty());
                  EXPECT_TRUE(options.is_write_through());
                  return success_stream.AddAction("Write/3");
                });
        return stream;
      });

  // Create an inactive completion queue to avoid flakes due to timing
  google::cloud::CompletionQueue cq(mock_cq);
  auto shutdown = std::make_shared<SessionShutdownManager>();
  StreamingSubscriptionBatchSource::TimerConfig timer_config;
  timer_config.clock = mock_clock.AsStdFunction();
  timer_config.period = kHz;
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      cq, shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      AckBatchingConfig(kBatchSize, kAckHz), std::move(timer_config));

  auto done = shutdown->Start({});
  uut->Start([](StatusOr<google::pubsub::v1::StreamingPullResponse> const&) {});
  auto periodic = timer.PopFront();                // MakeRelativeTimer()
  success_stream.WaitForAction().set_value(true);  // Start()
  success_stream.WaitForAction().set_value(true);  // Write()
  success_stream.WaitForAction().set_value(true);  // Read()
  async.PopFront().set_value();                    // RunAsync()
  auto last_read = success_stream.WaitForAction();

  for (int i = 0; i != kBatchSize; ++i) {
    uut->AckMessage("fake-b0-" + std::to_string(i));
  }
  // There should have been enough messages to trigger a Write() request.
  success_stream.WaitForAction().set_value(true);

  for (int i = 0; i != kBatchSize; ++i) {
    uut->NackMessage("fake-b1-" + std::to_string(i));
  }
  // There should have been enough messages to trigger a Write() request.
  success_stream.WaitForAction().set_value(true);

  for (int i = 0; i != kBatchSize / 2; ++i) {
    uut->AckMessage("fake-b2-" + std::to_string(i));
  }
  // Triggering the clock now should have no effect.
  periodic.set_value();
  periodic = timer.PopFront();
  // Advance the clock to the pointer where it should trigger a flush
  mocked_now = start + 2 * kAckHz;
  periodic.set_value();

  // That should trigger the request
  success_stream.WaitForAction().set_value(true);

  shutdown->MarkAsShutdown("test", {});
  uut->Shutdown();
  last_read.set_value(false);                      // Read()
  success_stream.WaitForAction().set_value(true);  // Finish()

  EXPECT_THAT(done.get(), StatusIs(StatusCode::kOk));
}

TEST(StreamingSubscriptionBatchSourceTest, AckLeaseRefresh) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";

  // We will configure StreamingSubscriptionBatchSource's to use this period
  // in its periodic timer.
  auto constexpr kHz = std::chrono::milliseconds(42);

  // We will configure StreamingSubscriptionBatchSource to flush leases every
  auto constexpr kLeaseHz = std::chrono::seconds(7);

  // We mock the wall clock by changing this variable, we start with an easy
  // to recognize value.
  auto start = std::chrono::system_clock::time_point{} +
               std::chrono::seconds(1000000000ULL);
  std::chrono::system_clock::time_point mocked_now = start;
  MockFunction<std::chrono::system_clock::time_point()> mock_clock;
  EXPECT_CALL(mock_clock, Call).WillRepeatedly([&] { return mocked_now; });

  AsyncSequencer<void> async;
  AsyncSequencer<void> timer;
  auto mock_cq =
      std::make_shared<google::cloud::testing_util::MockCompletionQueueImpl>();
  EXPECT_CALL(*mock_cq, MakeRelativeTimer)
      .WillRepeatedly([&](std::chrono::nanoseconds duration) {
        EXPECT_EQ(duration, kHz);
        using std::chrono::system_clock;
        auto const d =
            std::chrono::duration_cast<system_clock::duration>(duration);
        auto deadline = mocked_now + d;
        return timer.PushBack().then(
            [deadline](future<void>) { return make_status_or(deadline); });
      });
  EXPECT_CALL(*mock_cq, RunAsync)
      .WillRepeatedly([&async](std::unique_ptr<internal::RunAsyncBase> f) {
        struct MoveCapture {
          std::unique_ptr<internal::RunAsyncBase> function;
          void operator()(future<void>) const { function->exec(); }
        };
        return async.PushBack().then(MoveCapture{std::move(f)});
      });

  auto constexpr kBatchSize = 10;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();
  AsyncSequencer<int> async_pull;
  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue&,
                    std::unique_ptr<grpc::ClientContext>,
                    google::pubsub::v1::StreamingPullRequest const&) {
        auto stream = absl::make_unique<pubsub_testing::MockAsyncPullStream>();
        using Response = google::pubsub::v1::StreamingPullResponse;
        using Request = google::pubsub::v1::StreamingPullRequest;

        auto mock_start = [&async_pull] {
          return async_pull.PushBack("Start").then(
              [](future<int>) { return true; });
        };
        auto mock_write = [&async_pull](Unused, Unused) {
          return async_pull.PushBack("Write").then(
              [](future<int>) { return true; });
        };
        auto mock_read = [&async_pull] {
          return async_pull.PushBack("Read").then([](future<int> f) {
            auto size = f.get();
            if (size < 0) return absl::optional<Response>{};
            Response response;
            for (int i = 0; i != size; ++i) {
              auto& m = *response.add_received_messages();
              m.set_ack_id("ack-" + std::to_string(i));
              m.mutable_message()->set_message_id("msg-" + std::to_string(i));
            }
            return absl::make_optional(std::move(response));
          });
        };
        auto mock_finish = [&async_pull] {
          return async_pull.PushBack("Finish").then([](future<int> f) {
            if (f.get() == 0) return Status{};
            return Status{StatusCode::kUnknown, "mock-error"};
          });
        };

        EXPECT_CALL(*stream, Start).WillOnce(mock_start);
        EXPECT_CALL(*stream, Write).WillOnce(mock_write);
        EXPECT_CALL(*stream, Cancel).Times(AtMost(1));
        EXPECT_CALL(*stream, Read).WillRepeatedly(mock_read);
        EXPECT_CALL(*stream, Finish).WillOnce(mock_finish);

        EXPECT_CALL(*stream,
                    Write(Property(&Request::subscription, std::string{}), _))
            .WillOnce([&async_pull](Request const& request, Unused) mutable {
              EXPECT_THAT(request.ack_ids(), ElementsAre("ack-0", "ack-3"));
              EXPECT_THAT(request.modify_deadline_ack_ids(),
                          UnorderedElementsAre("ack-1", "ack-2", "ack-4"));
              // The exact location of the Nack is an implementation detail, but
              // it should be there, and should be a Nack.
              int index = 0;
              for (auto const& a : request.modify_deadline_ack_ids()) {
                if (a == "ack-1") {
                  EXPECT_EQ(0, request.modify_deadline_seconds(index));
                  break;
                }
                ++index;
              }
              return async_pull.PushBack("Write/Ack").then([](future<int>) {
                return true;
              });
            });

        return stream;
      });

  // Create an inactive completion queue to avoid flakes due to timing
  google::cloud::CompletionQueue cq(mock_cq);
  auto shutdown = std::make_shared<SessionShutdownManager>();
  StreamingSubscriptionBatchSource::TimerConfig timer_config;
  timer_config.clock = mock_clock.AsStdFunction();
  timer_config.period = kHz;
  timer_config.lease_refresh = kLeaseHz;
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      cq, shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      AckBatchingConfig(kBatchSize, std::chrono::hours(24)),
      std::move(timer_config));

  auto done = shutdown->Start({});
  uut->Start([](StatusOr<google::pubsub::v1::StreamingPullResponse> const&) {});
  auto periodic = timer.PopFront();    // MakeRelativeTimer()
  async_pull.PopFront().set_value(0);  // Start()
  async_pull.PopFront().set_value(0);  // Write()
  async_pull.PopFront().set_value(5);  // Read()
  async.PopFront().set_value();        // RunAsync(ReadLoop())
  auto read = async_pull.PopFront();

  uut->AckMessage("ack-0");
  uut->AckMessage("ack-3");
  uut->NackMessage("ack-1");

  // A timer trigger should have no effect because the clock has not advanced.
  periodic.set_value();
  periodic = timer.PopFront();
  // Advance the clock to a point where the leases should be refreshed and fire
  // the timer.
  mocked_now = start + kLeaseHz + std::chrono::seconds(1);
  periodic.set_value();
  periodic = timer.PopFront();
  async_pull.PopFront().set_value(0);

  shutdown->MarkAsShutdown("test", {});
  uut->Shutdown();
  read.set_value(-1);                  // Read()
  async_pull.PopFront().set_value(0);  // Finish()

  EXPECT_THAT(done.get(), StatusIs(StatusCode::kOk));
}

TEST(StreamingSubscriptionBatchSourceTest, ReadErrorWaitsForWrite) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  auto const expected_status = Status{StatusCode::kNotFound, "gone"};
  FakeStream fake_stream(expected_status);

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue& cq,
                    std::unique_ptr<grpc::ClientContext> context,
                    google::pubsub::v1::StreamingPullRequest const& request) {
        auto stream =
            fake_stream.MakeWriteFailureStream(cq, std::move(context), request);
        using Request = google::pubsub::v1::StreamingPullRequest;
        // Add expectations for Write() calls with empty subscriptions, only
        // the first call has a non-empty value and it is already set.
        EXPECT_CALL(*stream,
                    Write(Property(&Request::subscription, std::string{}), _))
            .WillOnce(
                [&](google::pubsub::v1::StreamingPullRequest const& request,
                    grpc::WriteOptions const&) {
                  EXPECT_THAT(request.ack_ids(), ElementsAre("fake-001"));
                  return fake_stream.AddAction("Write");
                });
        return stream;
      });
  using CallbackArg = StatusOr<google::pubsub::v1::StreamingPullResponse>;
  ::testing::MockFunction<void(CallbackArg const&)> callback;
  EXPECT_CALL(callback, Call(StatusIs(StatusCode::kOk))).Times(1);

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start(callback.AsStdFunction());
  fake_stream.WaitForAction().set_value(true);  // Start()
  fake_stream.WaitForAction().set_value(true);  // Write()
  fake_stream.WaitForAction().set_value(true);  // Read()

  auto pending_read = fake_stream.WaitForAction();  // Read() start
  uut->AckMessage("fake-001");
  auto pending_write = fake_stream.WaitForAction();  // Write() start

  pending_read.set_value(false);  // Read() done
  shutdown->MarkAsShutdown("test", expected_status);
  uut->Shutdown();

  pending_write.set_value(true);                // Write() done
  fake_stream.WaitForAction().set_value(true);  // Finish()

  EXPECT_EQ(expected_status, done.get());
}

TEST(StreamingSubscriptionBatchSourceTest, WriteErrorWaitsForRead) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  auto const expected_status = Status{StatusCode::kNotFound, "gone"};
  FakeStream fake_stream(expected_status);

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue& cq,
                    std::unique_ptr<grpc::ClientContext> context,
                    google::pubsub::v1::StreamingPullRequest const& request) {
        auto stream =
            fake_stream.MakeWriteFailureStream(cq, std::move(context), request);
        using Request = google::pubsub::v1::StreamingPullRequest;
        // Add expectations for Write() calls with empty subscriptions, only
        // the first call has a non-empty value and it is already set.
        EXPECT_CALL(*stream,
                    Write(Property(&Request::subscription, std::string{}), _))
            .WillOnce(
                [&](google::pubsub::v1::StreamingPullRequest const& request,
                    grpc::WriteOptions const&) {
                  EXPECT_THAT(request.ack_ids(), ElementsAre("fake-001"));
                  return fake_stream.AddAction("Write");
                });
        return stream;
      });
  using CallbackArg = StatusOr<google::pubsub::v1::StreamingPullResponse>;
  ::testing::MockFunction<void(CallbackArg const&)> callback;
  EXPECT_CALL(callback, Call(StatusIs(StatusCode::kOk))).Times(1);

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start(callback.AsStdFunction());
  fake_stream.WaitForAction().set_value(true);  // Start()
  fake_stream.WaitForAction().set_value(true);  // Write()
  fake_stream.WaitForAction().set_value(true);  // Read()

  auto pending_read = fake_stream.WaitForAction();  // Read() start
  uut->AckMessage("fake-001");
  auto pending_write = fake_stream.WaitForAction();  // Write() start

  shutdown->MarkAsShutdown("test", expected_status);
  uut->Shutdown();

  pending_write.set_value(false);               // Write() done
  pending_read.set_value(false);                // Read() done
  fake_stream.WaitForAction().set_value(true);  // Finish()

  EXPECT_EQ(expected_status, done.get());
}

TEST(StreamingSubscriptionBatchSourceTest, ShutdownWithPendingRead) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;
  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();

  auto const expected_status = Status{};
  FakeStream fake_stream(expected_status);

  EXPECT_CALL(*mock, AsyncStreamingPull)
      .WillOnce([&](google::cloud::CompletionQueue& cq,
                    std::unique_ptr<grpc::ClientContext> context,
                    google::pubsub::v1::StreamingPullRequest const& request) {
        return fake_stream.MakeWriteFailureStream(cq, std::move(context),
                                                  request);
      });
  using CallbackArg = StatusOr<google::pubsub::v1::StreamingPullResponse>;
  ::testing::MockFunction<void(CallbackArg const&)> callback;
  EXPECT_CALL(callback, Call(StatusIs(StatusCode::kOk))).Times(0);

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start(callback.AsStdFunction());
  fake_stream.WaitForAction().set_value(true);      // Start()
  fake_stream.WaitForAction().set_value(true);      // Write()
  auto pending_read = fake_stream.WaitForAction();  // Read() start

  uut->Shutdown();
  shutdown->MarkAsShutdown("test", expected_status);

  pending_read.set_value(true);                 // Read() done
  fake_stream.WaitForAction().set_value(true);  // Finish()
  EXPECT_EQ(expected_status, done.get());
}

/// @test verify that a shutdown cancels the initial Read() call
TEST(StreamingSubscriptionBatchSourceTest, ShutdownWithPendingReadCancel) {
  auto subscription = pubsub::Subscription("test-project", "test-subscription");
  std::string const client_id = "fake-client-id";
  AutomaticallyCreatedBackgroundThreads background;

  auto mock = std::make_shared<pubsub_testing::MockSubscriberStub>();
  AsyncSequencer<bool> async;

  auto wait_and_check_name = [&async](std::string const& name) {
    auto p = async.PopFrontWithName();
    EXPECT_EQ(p.second, name);
    return std::move(p.first);
  };

  auto async_pull_mock = [&](google::cloud::CompletionQueue&,
                             std::unique_ptr<grpc::ClientContext>,
                             google::pubsub::v1::StreamingPullRequest const&) {
    using Response = google::pubsub::v1::StreamingPullResponse;
    using Request = google::pubsub::v1::StreamingPullRequest;
    auto start_response = [&async] {
      return async.PushBack("Start").then(
          [](future<bool> f) { return f.get(); });
    };
    auto write_response = [&async](Request const&,
                                   grpc::WriteOptions const&) mutable {
      return async.PushBack("Write").then(
          [](future<bool> f) { return f.get(); });
    };
    auto read_response = [&] {
      return async.PushBack("Read").then([](future<bool> f) {
        if (f.get()) return absl::make_optional(Response{});
        return absl::optional<Response>{};
      });
    };
    auto cancel = [&] { async.PushBack("Cancel"); };
    auto finish_response = [&] {
      return async.PushBack("Finish").then(
          [](future<bool>) { return Status{}; });
    };

    auto stream = absl::make_unique<pubsub_testing::MockAsyncPullStream>();
    EXPECT_CALL(*stream, Start).WillOnce(start_response);
    EXPECT_CALL(*stream, Write).WillRepeatedly(write_response);
    EXPECT_CALL(*stream, Read).WillRepeatedly(read_response);
    EXPECT_CALL(*stream, Cancel).WillRepeatedly(cancel);
    EXPECT_CALL(*stream, Finish).WillOnce(finish_response);

    return stream;
  };
  EXPECT_CALL(*mock, AsyncStreamingPull).WillOnce(async_pull_mock);

  using CallbackArg = StatusOr<google::pubsub::v1::StreamingPullResponse>;
  ::testing::MockFunction<void(CallbackArg const&)> callback;
  EXPECT_CALL(callback, Call(StatusIs(StatusCode::kOk))).Times(0);

  auto shutdown = std::make_shared<SessionShutdownManager>();
  auto uut = std::make_shared<StreamingSubscriptionBatchSource>(
      background.cq(), shutdown, mock, subscription.FullName(), client_id,
      TestSubscriptionOptions(), TestRetryPolicy(), TestBackoffPolicy(),
      TestBatchingConfig());

  auto done = shutdown->Start({});
  uut->Start(callback.AsStdFunction());

  wait_and_check_name("Start").set_value(true);
  wait_and_check_name("Write").set_value(true);
  auto read = wait_and_check_name("Read");

  uut->Shutdown();

  auto cancel = wait_and_check_name("Cancel");
  read.set_value(false);
  wait_and_check_name("Finish").set_value(true);

  shutdown->MarkAsShutdown("test", Status{});
  EXPECT_THAT(done.get(), StatusIs(StatusCode::kOk));
}

TEST(StreamingSubscriptionBatchSourceTest, StateOStream) {
  auto as_string = [](StreamingSubscriptionBatchSource::StreamState s) {
    std::ostringstream os;
    os << s;
    return std::move(os).str();
  };
  using StreamState = StreamingSubscriptionBatchSource::StreamState;
  EXPECT_EQ("kNull", as_string(StreamState::kNull));
  EXPECT_EQ("kActive", as_string(StreamState::kActive));
  EXPECT_EQ("kDisconnecting", as_string(StreamState::kDisconnecting));
  EXPECT_EQ("kFinishing", as_string(StreamState::kFinishing));
}

}  // namespace
}  // namespace GOOGLE_CLOUD_CPP_PUBSUB_NS
}  // namespace pubsub_internal
}  // namespace cloud
}  // namespace google
