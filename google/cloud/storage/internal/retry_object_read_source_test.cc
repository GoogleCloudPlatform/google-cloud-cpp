// Copyright 2019 Google LLC
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

#include "google/cloud/storage/client.h"
#include "google/cloud/storage/retry_policy.h"
#include "google/cloud/storage/testing/canonical_errors.h"
#include "google/cloud/storage/testing/mock_client.h"
#include "google/cloud/storage/testing/retry_tests.h"
#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/testing_util/chrono_literals.h"
#include <gmock/gmock.h>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
namespace {

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Invoke;
using testing::MockObjectReadSource;
using ::testing::Return;
using ::google::cloud::testing_util::chrono_literals::operator"" _us;
using ::google::cloud::storage::testing::canonical_errors::PermanentError;
using ::google::cloud::storage::testing::canonical_errors::TransientError;

class BackoffPolicyMockState {
 public:
  BackoffPolicyMockState() : num_calls_from_last_clone_(), num_clones_() {}

  MOCK_METHOD0(OnCompletionHook, std::chrono::milliseconds());

  std::chrono::milliseconds OnCompletion() {
    num_calls_from_last_clone_++;
    return OnCompletionHook();
  }

  int num_calls_from_last_clone_;
  int num_clones_;
};

// Pretend independent backoff policies, but be only one under the hood.
// This is a trick to count the number of `clone()` calls.
class BackoffPolicyMock : public BackoffPolicy {
 public:
  BackoffPolicyMock() : state_(new BackoffPolicyMockState) {}

  std::chrono::milliseconds OnCompletion() override {
    return state_->OnCompletion();
  }

  std::unique_ptr<BackoffPolicy> clone() const override {
    state_->num_calls_from_last_clone_ = 0;
    ++state_->num_clones_;
    return std::unique_ptr<BackoffPolicy>(new BackoffPolicyMock(*this));
  }

  int NumCallsFromLastClone() { return state_->num_calls_from_last_clone_; }
  int NumClones() { return state_->num_clones_; }

  std::shared_ptr<BackoffPolicyMockState> state_;
};

/// @test No failures scenario.
TEST(RetryObjectReadSourceTest, NoFailures) {
  auto raw_client = std::make_shared<testing::MockClient>();
  auto raw_source = new MockObjectReadSource;
  auto client = std::make_shared<RetryClient>(
      std::shared_ptr<internal::RawClient>(raw_client),
      LimitedErrorCountRetryPolicy(3), StrictIdempotencyPolicy(),
      ExponentialBackoffPolicy(1_us, 2_us, 2));

  EXPECT_CALL(*raw_client, ReadObject(_))
      .WillOnce(Invoke([raw_source](ReadObjectRangeRequest) {
        return std::unique_ptr<ObjectReadSource>(raw_source);
      }));
  EXPECT_CALL(*raw_source, Read(_, _)).WillOnce(Return(ReadSourceResult{}));

  auto source = client->ReadObject(ReadObjectRangeRequest{});
  ASSERT_STATUS_OK(source);
  ASSERT_STATUS_OK((*source)->Read(nullptr, 1024));
}

/// @test Permanent failure when creating the raw source
TEST(RetryObjectReadSourceTest, PermanentFailureOnSessionCreation) {
  auto raw_client = std::make_shared<testing::MockClient>();
  auto client = std::make_shared<RetryClient>(
      std::shared_ptr<internal::RawClient>(raw_client),
      LimitedErrorCountRetryPolicy(3), StrictIdempotencyPolicy(),
      ExponentialBackoffPolicy(1_us, 2_us, 2));

  EXPECT_CALL(*raw_client, ReadObject(_))
      .WillOnce(
          Invoke([](ReadObjectRangeRequest) { return PermanentError(); }));

  auto source = client->ReadObject(ReadObjectRangeRequest{});
  ASSERT_FALSE(source);
  EXPECT_EQ(PermanentError().code(), source.status().code());
}

/// @test Transient failures exhaust retry policy when creating the raw source
TEST(RetryObjectReadSourceTest, TransientFailuresExhaustOnSessionCreation) {
  auto raw_client = std::make_shared<testing::MockClient>();
  auto client = std::make_shared<RetryClient>(
      std::shared_ptr<internal::RawClient>(raw_client),
      LimitedErrorCountRetryPolicy(3), StrictIdempotencyPolicy(),
      ExponentialBackoffPolicy(1_us, 2_us, 2));

  EXPECT_CALL(*raw_client, ReadObject(_))
      .Times(4)
      .WillRepeatedly(
          Invoke([](ReadObjectRangeRequest) { return TransientError(); }));

  auto source = client->ReadObject(ReadObjectRangeRequest{});
  ASSERT_FALSE(source);
  EXPECT_EQ(TransientError().code(), source.status().code());
}

/// @test Recovery from a transient failures when creating the raw source
TEST(RetryObjectReadSourceTest, SessionCreationRecoversFromTransientFailures) {
  auto raw_client = std::make_shared<testing::MockClient>();
  auto raw_source = new MockObjectReadSource;
  auto client = std::make_shared<RetryClient>(
      std::shared_ptr<internal::RawClient>(raw_client),
      LimitedErrorCountRetryPolicy(3), StrictIdempotencyPolicy(),
      ExponentialBackoffPolicy(1_us, 2_us, 2));

  EXPECT_CALL(*raw_client, ReadObject(_))
      .WillOnce(Invoke([](ReadObjectRangeRequest) { return TransientError(); }))
      .WillOnce(Invoke([](ReadObjectRangeRequest) { return TransientError(); }))
      .WillOnce(Invoke([raw_source](ReadObjectRangeRequest) {
        return std::unique_ptr<ObjectReadSource>(raw_source);
      }));
  EXPECT_CALL(*raw_source, Read(_, _)).WillOnce(Return(ReadSourceResult{}));

  auto source = client->ReadObject(ReadObjectRangeRequest{});
  ASSERT_STATUS_OK(source);
  EXPECT_STATUS_OK((*source)->Read(nullptr, 1024));
}

/// @test A permanent error after a successful read
TEST(RetryObjectReadSourceTest, PermanentReadFailure) {
  auto raw_client = std::make_shared<testing::MockClient>();
  auto raw_source = new MockObjectReadSource;
  auto client = std::make_shared<RetryClient>(
      std::shared_ptr<internal::RawClient>(raw_client),
      LimitedErrorCountRetryPolicy(3), StrictIdempotencyPolicy(),
      ExponentialBackoffPolicy(1_us, 2_us, 2));

  EXPECT_CALL(*raw_client, ReadObject(_))
      .WillOnce(Invoke([raw_source](ReadObjectRangeRequest) {
        return std::unique_ptr<ObjectReadSource>(raw_source);
      }));
  EXPECT_CALL(*raw_source, Read(_, _))
      .WillOnce(Return(ReadSourceResult{}))
      .WillOnce(Return(PermanentError()));

  auto source = client->ReadObject(ReadObjectRangeRequest{});
  ASSERT_STATUS_OK(source);
  ASSERT_STATUS_OK((*source)->Read(nullptr, 1024));
  auto res = (*source)->Read(nullptr, 1024);
  ASSERT_FALSE(res);
  EXPECT_EQ(PermanentError().code(), res.status().code());
}

/// @test Test if backoff policy is reset on succes
TEST(RetryObjectReadSourceTest, BackoffPolicyResetOnSuccess) {
  auto raw_client = std::make_shared<testing::MockClient>();
  auto raw_source1 = new MockObjectReadSource;
  auto raw_source2 = new MockObjectReadSource;
  auto raw_source3 = new MockObjectReadSource;
  int num_backoff_policy_called = 0;
  BackoffPolicyMock backoff_policy_mock;
  EXPECT_CALL(*backoff_policy_mock.state_, OnCompletionHook())
      .WillRepeatedly(Invoke([&] {
        ++num_backoff_policy_called;
        return std::chrono::milliseconds(0);
      }));
  auto client = std::make_shared<RetryClient>(
      std::shared_ptr<internal::RawClient>(raw_client),
      LimitedErrorCountRetryPolicy(5), StrictIdempotencyPolicy(),
      backoff_policy_mock);

  EXPECT_EQ(0, num_backoff_policy_called);

  EXPECT_CALL(*raw_client, ReadObject(_))
      .WillOnce(Invoke([raw_source1](ReadObjectRangeRequest) {
        return std::unique_ptr<ObjectReadSource>(raw_source1);
      }))
      .WillOnce(Invoke([raw_source2](ReadObjectRangeRequest) {
        return std::unique_ptr<ObjectReadSource>(raw_source2);
      }))
      .WillOnce(Invoke([raw_source3](ReadObjectRangeRequest) {
        return std::unique_ptr<ObjectReadSource>(raw_source3);
      }));
  EXPECT_CALL(*raw_source1, Read(_, _)).WillOnce(Return(TransientError()));

  EXPECT_CALL(*raw_source2, Read(_, _)).WillOnce(Return(TransientError()));

  EXPECT_CALL(*raw_source3, Read(_, _)).WillOnce(Return(ReadSourceResult{}));

  auto source = client->ReadObject(ReadObjectRangeRequest{});
  ASSERT_STATUS_OK(source);
  // The policy was cloned twice by the ctor and once by the RetryClient
  EXPECT_EQ(3, backoff_policy_mock.NumClones());
  EXPECT_EQ(0, num_backoff_policy_called);

  // raw_source1 and raw_source2 fail, then a success
  ASSERT_STATUS_OK((*source)->Read(nullptr, 1024));
  // Two retries, so the backoff policy was called twice.
  EXPECT_EQ(2, num_backoff_policy_called);
  // The backoff should have been cloned during the read (after the successful
  // read, but not after a successful ReadObject).
  EXPECT_EQ(4, backoff_policy_mock.NumClones());
  // After backoff policy had been cloned, no OnFailure() was called.
  EXPECT_EQ(0, backoff_policy_mock.NumCallsFromLastClone());
}

/// @test Check that retry policy is shared between reads and resetting session
TEST(RetryObjectReadSourceTest, RetryPolicyExhaustedOnResetSession) {
  auto raw_client = std::make_shared<testing::MockClient>();
  auto raw_source1 = new MockObjectReadSource;
  auto client = std::make_shared<RetryClient>(
      std::shared_ptr<internal::RawClient>(raw_client),
      LimitedErrorCountRetryPolicy(3), StrictIdempotencyPolicy(),
      ExponentialBackoffPolicy(1_us, 2_us, 2));

  EXPECT_CALL(*raw_client, ReadObject(_))
      .WillOnce(Invoke([raw_source1](ReadObjectRangeRequest) {
        return std::unique_ptr<ObjectReadSource>(raw_source1);
      }))
      .WillOnce(Invoke([](ReadObjectRangeRequest) { return TransientError(); }))
      .WillOnce(Invoke([](ReadObjectRangeRequest) { return TransientError(); }))
      .WillOnce(
          Invoke([](ReadObjectRangeRequest) { return TransientError(); }));

  EXPECT_CALL(*raw_source1, Read(_, _))
      .WillOnce(Return(ReadSourceResult{}))
      .WillOnce(Return(TransientError()));

  auto source = client->ReadObject(ReadObjectRangeRequest{});
  ASSERT_STATUS_OK(source);
  ASSERT_STATUS_OK((*source)->Read(nullptr, 1024));
  auto res = (*source)->Read(nullptr, 1024);
  // It takes 4 retry attempts to exhaust the policy. Only a retry policy shared
  // between reads and resetting the session could exhaust it.
  ASSERT_FALSE(res);
  EXPECT_EQ(TransientError().code(), res.status().code());
  EXPECT_THAT(res.status().message(), HasSubstr("Retry policy exhausted"));
}

}  // namespace
}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
