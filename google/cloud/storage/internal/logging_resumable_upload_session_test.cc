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

#include "google/cloud/storage/internal/logging_resumable_upload_session.h"
#include "google/cloud/storage/testing/mock_client.h"
#include "google/cloud/log.h"
#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/testing_util/capture_log_lines_backend.h"
#include "absl/memory/memory.h"
#include <gmock/gmock.h>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
namespace {

using ::google::cloud::testing_util::CaptureLogLinesBackend;
using ::testing::_;
using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::ReturnRef;

class LoggingResumableUploadSessionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    log_backend_ = std::make_shared<CaptureLogLinesBackend>();
    log_backend_id_ =
        google::cloud::LogSink::Instance().AddBackend(log_backend_);
  }
  void TearDown() override {
    google::cloud::LogSink::Instance().RemoveBackend(log_backend_id_);
    log_backend_id_ = 0;
    log_backend_.reset();
  }

  std::shared_ptr<CaptureLogLinesBackend> log_backend_ = nullptr;
  long log_backend_id_ = 0;  // NOLINT(google-runtime-int)
};

TEST_F(LoggingResumableUploadSessionTest, UploadChunk) {
  auto mock = absl::make_unique<testing::MockResumableUploadSession>();

  std::string const payload = "test-payload-data";
  EXPECT_CALL(*mock, UploadChunk(_))
      .WillOnce([&](ConstBufferSequence const& p) {
        EXPECT_THAT(p, ElementsAre(ConstBuffer{payload}));
        return StatusOr<ResumableUploadResponse>(
            AsStatus(HttpResponse{503, "uh oh", {}}));
      });

  LoggingResumableUploadSession session(std::move(mock));

  auto result = session.UploadChunk({{payload}});
  EXPECT_EQ(StatusCode::kUnavailable, result.status().code());
  EXPECT_EQ("uh oh", result.status().message());

  EXPECT_THAT(log_backend_->log_lines, Contains(HasSubstr("[UNAVAILABLE]")));
}

TEST_F(LoggingResumableUploadSessionTest, UploadFinalChunk) {
  auto mock = absl::make_unique<testing::MockResumableUploadSession>();

  std::string const payload = "test-payload-data";
  EXPECT_CALL(*mock, UploadFinalChunk(_, _))
      .WillOnce([&](ConstBufferSequence const& p, std::uint64_t s) {
        EXPECT_THAT(p, ElementsAre(ConstBuffer{payload}));
        EXPECT_EQ(513 * 1024, s);
        return StatusOr<ResumableUploadResponse>(
            AsStatus(HttpResponse{503, "uh oh", {}}));
      });

  LoggingResumableUploadSession session(std::move(mock));

  auto result = session.UploadFinalChunk({{payload}}, 513 * 1024);
  EXPECT_EQ(StatusCode::kUnavailable, result.status().code());
  EXPECT_EQ("uh oh", result.status().message());

  EXPECT_THAT(log_backend_->log_lines,
              Contains(HasSubstr("upload_size=" + std::to_string(513 * 1024))));
  EXPECT_THAT(log_backend_->log_lines, Contains(HasSubstr("[UNAVAILABLE]")));
}

TEST_F(LoggingResumableUploadSessionTest, ResetSession) {
  auto mock = absl::make_unique<testing::MockResumableUploadSession>();

  EXPECT_CALL(*mock, ResetSession()).WillOnce([&]() {
    return StatusOr<ResumableUploadResponse>(
        Status(AsStatus(HttpResponse{308, "uh oh", {}})));
  });

  LoggingResumableUploadSession session(std::move(mock));

  auto result = session.ResetSession();
  EXPECT_EQ(StatusCode::kFailedPrecondition, result.status().code());
  EXPECT_EQ("uh oh", result.status().message());

  EXPECT_THAT(log_backend_->log_lines,
              Contains(HasSubstr("[FAILED_PRECONDITION]")));
}

TEST_F(LoggingResumableUploadSessionTest, NextExpectedByte) {
  auto mock = absl::make_unique<testing::MockResumableUploadSession>();

  EXPECT_CALL(*mock, next_expected_byte()).WillOnce([&]() {
    return 512 * 1024U;
  });

  LoggingResumableUploadSession session(std::move(mock));

  auto result = session.next_expected_byte();
  EXPECT_EQ(512 * 1024, result);

  EXPECT_THAT(log_backend_->log_lines,
              Contains(HasSubstr(std::to_string(512 * 1024))));
}

TEST_F(LoggingResumableUploadSessionTest, LastResponseOk) {
  auto mock = absl::make_unique<testing::MockResumableUploadSession>();

  const StatusOr<ResumableUploadResponse> last_response(ResumableUploadResponse{
      "upload url", 1, {}, ResumableUploadResponse::kInProgress, {}});
  EXPECT_CALL(*mock, last_response()).WillOnce(ReturnRef(last_response));

  LoggingResumableUploadSession session(std::move(mock));

  auto result = session.last_response();
  ASSERT_STATUS_OK(result);
  EXPECT_EQ(result.value(), last_response.value());
  EXPECT_THAT(log_backend_->log_lines, Contains(HasSubstr("upload url")));
  EXPECT_THAT(log_backend_->log_lines, Contains(HasSubstr("payload={}")));
}

TEST_F(LoggingResumableUploadSessionTest, LastResponseBadStatus) {
  auto mock = absl::make_unique<testing::MockResumableUploadSession>();

  const StatusOr<ResumableUploadResponse> last_response(
      Status(StatusCode::kFailedPrecondition, "something bad"));
  EXPECT_CALL(*mock, last_response()).WillOnce(ReturnRef(last_response));

  LoggingResumableUploadSession session(std::move(mock));

  auto result = session.last_response();
  EXPECT_EQ(StatusCode::kFailedPrecondition, result.status().code());
  EXPECT_EQ("something bad", result.status().message());

  EXPECT_THAT(log_backend_->log_lines,
              Contains(HasSubstr("[FAILED_PRECONDITION]")));
}

}  // namespace
}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
