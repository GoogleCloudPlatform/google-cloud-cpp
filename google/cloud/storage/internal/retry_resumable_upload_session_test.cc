// Copyright 2018 Google LLC
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

#include "google/cloud/storage/internal/retry_resumable_upload_session.h"
#include "google/cloud/internal/make_unique.h"
#include "google/cloud/storage/testing/canonical_errors.h"
#include "google/cloud/storage/testing/mock_client.h"
#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/testing_util/chrono_literals.h"
#include <gmock/gmock.h>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
namespace {

using ::google::cloud::storage::testing::canonical_errors::PermanentError;
using ::google::cloud::storage::testing::canonical_errors::TransientError;
using ::google::cloud::testing_util::chrono_literals::operator"" _ms;
using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::ReturnRef;

class RetryResumableUploadSessionTest : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}
};

/// @test Verify that transient failures are handled as expected.
TEST_F(RetryResumableUploadSessionTest, HandleTransient) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(quantum, '0');

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns transient error
  // 2. ResetSession() -> returns transient error
  // 3. ResetSession() -> returns success (0 bytes committed)
  // 4. UploadChunk() -> returns success (quantum bytes committed)
  // 5. UploadChunk() -> returns transient error
  // 6 .ResetSession() -> returns success (quantum bytes committed)
  // 7. UploadChunk() -> returns success (2 * quantum bytes committed)
  // 8. UploadChunk() -> returns success (2 * quantum bytes committed)
  //
  EXPECT_CALL(*mock, UploadChunk(_))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(1, count);
        EXPECT_EQ(payload, p);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(4, count);
        EXPECT_EQ(payload, p);
        return make_status_or(ResumableUploadResponse{
            "", quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(5, count);
        EXPECT_EQ(payload, p);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(7, count);
        EXPECT_EQ(payload, p);
        return make_status_or(ResumableUploadResponse{
            "", 2 * quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(8, count);
        EXPECT_EQ(payload, p);
        return make_status_or(ResumableUploadResponse{
            "", 3 * quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }));

  EXPECT_CALL(*mock, ResetSession())
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(2, count);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(3, count);
        return make_status_or(ResumableUploadResponse{
            "", 0, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(6, count);
        return make_status_or(ResumableUploadResponse{
            "", quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }));

  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(10).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response;
  response = session.UploadChunk(payload);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(quantum - 1, response->last_committed_byte);

  response = session.UploadChunk(payload);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(2 * quantum - 1, response->last_committed_byte);

  response = session.UploadChunk(payload);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(3 * quantum - 1, response->last_committed_byte);
}

/// @test Verify that a permanent error on UploadChunk results in a failure.
TEST_F(RetryResumableUploadSessionTest, PermanentErrorOnUpload) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(quantum, '0');

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns permanent error, the request aborts.
  //
  EXPECT_CALL(*mock, UploadChunk(_)).WillOnce(Invoke([&](std::string const& p) {
    ++count;
    EXPECT_EQ(1, count);
    EXPECT_EQ(payload, p);
    return StatusOr<ResumableUploadResponse>(PermanentError());
  }));

  // We only tolerate 4 transient errors, the first call to UploadChunk() will
  // consume the full budget.
  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(10).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response = session.UploadChunk(payload);
  EXPECT_FALSE(response.ok());
}

/// @test Verify that a permanent error on ResetSession results in a failure.
TEST_F(RetryResumableUploadSessionTest, PermanentErrorOnReset) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(quantum, '0');

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns transient error
  // 2. ResetSession() -> returns permanent, the request aborts.
  //
  EXPECT_CALL(*mock, UploadChunk(_)).WillOnce(Invoke([&](std::string const& p) {
    ++count;
    EXPECT_EQ(1, count);
    EXPECT_EQ(payload, p);
    return StatusOr<ResumableUploadResponse>(TransientError());
  }));

  EXPECT_CALL(*mock, ResetSession()).WillOnce(Invoke([&]() {
    ++count;
    EXPECT_EQ(2, count);
    return StatusOr<ResumableUploadResponse>(PermanentError());
  }));

  // We only tolerate 4 transient errors, the first call to UploadChunk() will
  // consume the full budget.
  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(10).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response = session.UploadChunk(payload);
  EXPECT_FALSE(response.ok());
}

/// @test Verify that too many transients on ResetSession results in a failure.
TEST_F(RetryResumableUploadSessionTest, TooManyTransientOnUploadChunk) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(quantum, '0');

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns transient error
  // 2. ResetSession() -> returns success (0 bytes committed)
  // 3. UploadChunk() -> returns transient error
  // 4. ResetSession() -> returns success (0 bytes committed)
  // 5. UploadChunk() -> returns transient error, the policy is exhausted.
  //
  EXPECT_CALL(*mock, UploadChunk(_))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(1, count);
        EXPECT_EQ(payload, p);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(3, count);
        EXPECT_EQ(payload, p);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(5, count);
        EXPECT_EQ(payload, p);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }));

  EXPECT_CALL(*mock, ResetSession())
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(2, count);
        return make_status_or(ResumableUploadResponse{
            "", 0, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(4, count);
        return make_status_or(ResumableUploadResponse{
            "", 0, {}, ResumableUploadResponse::kInProgress});
      }));

  // We only tolerate 4 transient errors, the first call to UploadChunk() will
  // consume the full budget.
  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(2).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response = session.UploadChunk(payload);
  EXPECT_FALSE(response.ok());
  EXPECT_EQ(response.status().code(), TransientError().code());
  EXPECT_THAT(response.status().message(), HasSubstr("Retry policy exhausted"));
}

/// @test Verify that too many transients on ResetSession result in a failure.
TEST_F(RetryResumableUploadSessionTest, TooManyTransientOnReset) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(quantum, '0');

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns transient error
  // 2. ResetSession() -> returns transient error
  // 3. ResetSession() -> returns success (0 bytes committed)
  // 4. UploadChunk() -> returns success (quantum bytes committed)
  // 5. UploadChunk() -> returns transient error, the policy is exhausted.
  //
  EXPECT_CALL(*mock, UploadChunk(_))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(1, count);
        EXPECT_EQ(payload, p);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(4, count);
        EXPECT_EQ(payload, p);
        return make_status_or(ResumableUploadResponse{
            "", quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(5, count);
        EXPECT_EQ(payload, p);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }));

  EXPECT_CALL(*mock, ResetSession())
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(2, count);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(3, count);
        return make_status_or(ResumableUploadResponse{
            "", 0, {}, ResumableUploadResponse::kInProgress});
      }));

  // We only tolerate 4 transient errors, the first call to UploadChunk() will
  // consume the full budget.
  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(2).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response = session.UploadChunk(payload);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(quantum - 1, response->last_committed_byte);

  response = session.UploadChunk(payload);
  EXPECT_FALSE(response.ok());
}

/// @test Verify that a permanent error on UploadFinalChunk results in a
/// failure.
TEST_F(RetryResumableUploadSessionTest, PermanentErrorOnUploadFinalChunk) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(quantum, '0');

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns permanent error, the request aborts.
  //
  EXPECT_CALL(*mock, UploadFinalChunk(_, _))
      .WillOnce(Invoke([&](std::string const& p, std::size_t s) {
        ++count;
        EXPECT_EQ(1, count);
        EXPECT_EQ(payload, p);
        EXPECT_EQ(quantum, s);
        return StatusOr<ResumableUploadResponse>(PermanentError());
      }));

  // We only tolerate 4 transient errors, the first call to UploadChunk() will
  // consume the full budget.
  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(10).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response =
      session.UploadFinalChunk(payload, quantum);
  EXPECT_FALSE(response.ok());
  EXPECT_EQ(PermanentError().code(), response.status().code());
}

/// @test Verify that too many transients on UploadFinalChunk result in a
/// failure.
TEST_F(RetryResumableUploadSessionTest, TooManyTransientOnUploadFinalChunk) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(quantum, '0');

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadFinalChunk() -> returns transient error
  // 2. ResetSession() -> returns success (0 bytes committed)
  // 3. UploadFinalChunk() -> returns transient error
  // 4. ResetSession() -> returns success (0 bytes committed)
  // 5. UploadFinalChunk() -> returns transient error, the policy is exhausted.
  //
  EXPECT_CALL(*mock, UploadFinalChunk(_, _))
      .WillOnce(Invoke([&](std::string const& p, std::size_t s) {
        ++count;
        EXPECT_EQ(1, count);
        EXPECT_EQ(payload, p);
        EXPECT_EQ(quantum, s);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p, std::size_t s) {
        ++count;
        EXPECT_EQ(3, count);
        EXPECT_EQ(payload, p);
        EXPECT_EQ(quantum, s);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p, std::size_t s) {
        ++count;
        EXPECT_EQ(5, count);
        EXPECT_EQ(payload, p);
        EXPECT_EQ(quantum, s);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }));

  EXPECT_CALL(*mock, ResetSession())
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(2, count);
        return make_status_or(ResumableUploadResponse{
            "", 0, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(4, count);
        return make_status_or(ResumableUploadResponse{
            "", 0, {}, ResumableUploadResponse::kInProgress});
      }));

  // We only tolerate 4 transient errors, the first call to UploadChunk() will
  // consume the full budget.
  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(2).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response =
      session.UploadFinalChunk(payload, quantum);
  EXPECT_FALSE(response.ok());
}

TEST(RetryResumableUploadSession, Done) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();
  EXPECT_CALL(*mock, done()).WillOnce(Return(true));

  RetryResumableUploadSession session(std::move(mock), {}, {});
  EXPECT_TRUE(session.done());
}

TEST(RetryResumableUploadSession, LastResponse) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();
  StatusOr<ResumableUploadResponse> const last_response(
      ResumableUploadResponse{"url", 1, {}, ResumableUploadResponse::kDone});
  EXPECT_CALL(*mock, last_response()).WillOnce(ReturnRef(last_response));

  RetryResumableUploadSession session(std::move(mock), {}, {});
  StatusOr<ResumableUploadResponse> const result = session.last_response();
  ASSERT_STATUS_OK(result);
  EXPECT_EQ(result.value(), last_response.value());
}

TEST(RetryResumableUploadSession, UploadChunkPolicyExhaustedOnStart) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();
  RetryResumableUploadSession session(
      std::move(mock), LimitedTimeRetryPolicy(std::chrono::seconds(0)).clone(),
      {});
  auto res = session.UploadChunk(
      std::string(UploadChunkRequest::kChunkSizeQuantum, 'X'));
  ASSERT_FALSE(res);
  EXPECT_EQ(StatusCode::kDeadlineExceeded, res.status().code());
  EXPECT_THAT(res.status().message(),
              HasSubstr("Retry policy exhausted before first attempt"));
}

TEST(RetryResumableUploadSession, UploadFinalChunkPolicyExhaustedOnStart) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();
  RetryResumableUploadSession session(
      std::move(mock), LimitedTimeRetryPolicy(std::chrono::seconds(0)).clone(),
      {});
  auto res = session.UploadFinalChunk("blah", 4);
  ASSERT_FALSE(res);
  EXPECT_EQ(StatusCode::kDeadlineExceeded, res.status().code());
  EXPECT_THAT(res.status().message(),
              HasSubstr("Retry policy exhausted before first attempt"));
}

TEST(RetryResumableUploadSession, ResetSessionPolicyExhaustedOnStart) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();
  RetryResumableUploadSession session(
      std::move(mock), LimitedTimeRetryPolicy(std::chrono::seconds(0)).clone(),
      {});
  auto res = session.ResetSession();
  ASSERT_FALSE(res);
  EXPECT_EQ(StatusCode::kDeadlineExceeded, res.status().code());
  EXPECT_THAT(res.status().message(),
              HasSubstr("Retry policy exhausted before first attempt"));
}

/// @test Verify that transient failures which move next_bytes are handled
TEST_F(RetryResumableUploadSessionTest, HandleTransientPartialFailures) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(std::string(quantum, 'X') +
                            std::string(quantum, 'Y') +
                            std::string(quantum, 'Z'));

  std::string const payload_final(std::string(quantum, 'A') +
                                  std::string(quantum, 'B') +
                                  std::string(quantum, 'C'));

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns transient error
  // 2. ResetSession() -> returns success (quantum bytes committed)
  // 3. UploadChunk() -> returns transient error
  // 4. ResetSession() -> returns success (2 * quantum bytes committed)
  // 5. UploadChunk() -> returns success (3 * quantum bytes committed)
  //
  // 6. UploadFinalChunk() -> returns transient error
  // 7. ResetSession() -> returns success (4 * quantum bytes committed)
  // 8. UploadFinalChunk() -> returns transient error
  // 9. ResetSession() -> returns success (5 * quantum bytes committed)
  // 10. UploadFinalChunk() -> returns success (6 * quantum bytes committed)
  EXPECT_CALL(*mock, UploadChunk(_))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(1, count);
        EXPECT_EQ(3 * quantum, p.size());
        EXPECT_EQ('X', p[0]);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(3, count);
        EXPECT_EQ(2 * quantum, p.size());
        EXPECT_EQ('Y', p[0]);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p) {
        ++count;
        EXPECT_EQ(5, count);
        EXPECT_EQ(quantum, p.size());
        EXPECT_EQ('Z', p[0]);
        return make_status_or(ResumableUploadResponse{
            "", 3 * quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }));
  EXPECT_CALL(*mock, UploadFinalChunk(_, _))
      .WillOnce(Invoke([&](std::string const& p, std::size_t) {
        ++count;
        EXPECT_EQ(6, count);
        EXPECT_EQ(3 * quantum, p.size());
        EXPECT_EQ('A', p[0]);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p, std::size_t) {
        ++count;
        EXPECT_EQ(8, count);
        EXPECT_EQ(2 * quantum, p.size());
        EXPECT_EQ('B', p[0]);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }))
      .WillOnce(Invoke([&](std::string const& p, std::size_t) {
        ++count;
        EXPECT_EQ(10, count);
        EXPECT_EQ(quantum, p.size());
        EXPECT_EQ('C', p[0]);
        return make_status_or(ResumableUploadResponse{
            "", 6 * quantum - 1, {}, ResumableUploadResponse::kDone});
      }));

  EXPECT_CALL(*mock, ResetSession())
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(2, count);
        return make_status_or(ResumableUploadResponse{
            "", quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(4, count);
        return make_status_or(ResumableUploadResponse{
            "", 2 * quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(7, count);
        return make_status_or(ResumableUploadResponse{
            "", 4 * quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&]() {
        ++count;
        EXPECT_EQ(9, count);
        return make_status_or(ResumableUploadResponse{
            "", 5 * quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }));
  // `next_expected_byte()` should always precede `Upload[Final]Chunk` - this is
  // reflected in expectations on `count`.
  EXPECT_CALL(*mock, next_expected_byte())
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(0, count);
        return 0;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(2, count);
        return quantum;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(4, count);
        return 2 * quantum;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(5, count);
        return 3 * quantum;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(7, count);
        return 4 * quantum;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(9, count);
        return 5 * quantum;
      }));

  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(10).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response;
  response = session.UploadChunk(payload);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(3 * quantum - 1, response->last_committed_byte);

  response = session.UploadFinalChunk(payload_final, 6 * quantum);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(6 * quantum - 1, response->last_committed_byte);
}

/// @test Verify that erroneous server behavior (uncommitting data) is handled.
TEST_F(RetryResumableUploadSessionTest, UploadFinalChunkUncommitted) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(std::string(quantum, 'X'));

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns success (quantum bytes committed)
  //
  // 2. UploadFinalChunk() -> returns transient error
  // 3. ResetSession() -> returns success (0 bytes committed)
  EXPECT_CALL(*mock, UploadChunk(_)).WillOnce(Invoke([&](std::string const&) {
    ++count;
    EXPECT_EQ(1, count);
    return make_status_or(ResumableUploadResponse{
        "", quantum - 1, {}, ResumableUploadResponse::kInProgress});
  }));
  EXPECT_CALL(*mock, UploadFinalChunk(_, _))
      .WillOnce(Invoke([&](std::string const&, std::size_t) {
        ++count;
        EXPECT_EQ(2, count);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }));

  EXPECT_CALL(*mock, ResetSession()).WillOnce(Invoke([&]() {
    ++count;
    EXPECT_EQ(3, count);
    return make_status_or(ResumableUploadResponse{
        "", 0, {}, ResumableUploadResponse::kInProgress});
  }));

  // `next_expected_byte()` should always precede `Upload[Final]Chunk` - this is
  // reflected in expectations on `count`.
  EXPECT_CALL(*mock, next_expected_byte())
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(0, count);
        return 0;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1, count);
        return quantum;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(3, count);
        // pretend the server 'uncommitted' data
        return 0;
      }));

  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(10).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response;
  response = session.UploadChunk(payload);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(quantum - 1, response->last_committed_byte);

  response = session.UploadFinalChunk(payload, 2 * quantum);
  ASSERT_FALSE(response);
  EXPECT_EQ(StatusCode::kInternal, response.status().code());
  EXPECT_THAT(response.status().message(), HasSubstr("github"));
}

/// @test Verify that erroneous server behavior (uncommitting data) is handled.
TEST_F(RetryResumableUploadSessionTest, UploadChunkUncommitted) {
  auto mock = google::cloud::internal::make_unique<
      testing::MockResumableUploadSession>();

  auto const quantum = UploadChunkRequest::kChunkSizeQuantum;
  std::string const payload(std::string(quantum, 'X'));

  // Keep track of the sequence of calls.
  int count = 0;
  // The sequence of messages is split across two EXPECT_CALL() and hard to see,
  // basically we want this to happen:
  //
  // 1. UploadChunk() -> returns success (quantum bytes committed)
  //
  // 2. UploadChunk() -> returns transient error
  // 3. ResetSession() -> returns success (0 bytes committed)
  EXPECT_CALL(*mock, UploadChunk(_))
      .WillOnce(Invoke([&](std::string const&) {
        ++count;
        EXPECT_EQ(1, count);
        return make_status_or(ResumableUploadResponse{
            "", quantum - 1, {}, ResumableUploadResponse::kInProgress});
      }))
      .WillOnce(Invoke([&](std::string const&) {
        ++count;
        EXPECT_EQ(2, count);
        return StatusOr<ResumableUploadResponse>(TransientError());
      }));

  EXPECT_CALL(*mock, ResetSession()).WillOnce(Invoke([&]() {
    ++count;
    EXPECT_EQ(3, count);
    return make_status_or(ResumableUploadResponse{
        "", 0, {}, ResumableUploadResponse::kInProgress});
  }));

  // `next_expected_byte()` should always precede `Upload[Final]Chunk` - this is
  // reflected in expectations on `count`.
  EXPECT_CALL(*mock, next_expected_byte())
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(0, count);
        return 0;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1, count);
        return quantum;
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(3, count);
        // pretend the server 'uncommitted' data
        return 0;
      }));

  RetryResumableUploadSession session(
      std::move(mock), LimitedErrorCountRetryPolicy(10).clone(),
      ExponentialBackoffPolicy(10_ms, 160_ms, 2).clone());

  StatusOr<ResumableUploadResponse> response;
  response = session.UploadChunk(payload);
  EXPECT_STATUS_OK(response);
  EXPECT_EQ(quantum - 1, response->last_committed_byte);

  response = session.UploadChunk(payload);
  ASSERT_FALSE(response);
  EXPECT_EQ(StatusCode::kInternal, response.status().code());
  EXPECT_THAT(response.status().message(), HasSubstr("github"));
}

}  // namespace
}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
