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

#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/status.h"
#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>

using ::google::cloud::Status;
using ::google::cloud::StatusCode;
using ::google::cloud::StatusOr;

TEST(AssertOkTest, AssertionOk) {
  Status status;
  ASSERT_STATUS_OK(status);
}

TEST(AssertOkTest, AssertionOkStatusOr) {
  StatusOr<int> status_or(42);
  ASSERT_STATUS_OK(status_or);
}

TEST(AssertOkTest, AssertionOkDescription) {
  Status status;
  ASSERT_STATUS_OK(status) << "OK is not OK?";
}

TEST(AssertOkTest, AssertionOkDescriptionStatusOr) {
  StatusOr<int> status_or(42);
  ASSERT_STATUS_OK(status_or) << "OK is not OK?";
}

TEST(AssertOkTest, AssertionFailed) {
  EXPECT_FATAL_FAILURE(
      {
        Status status(StatusCode::kInternal, "oh no!");
        ASSERT_STATUS_OK(status);
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)");
}

TEST(AssertOkTest, AssertionFailedStatusOr) {
  EXPECT_FATAL_FAILURE(
      {
        StatusOr<int> status_or(Status(StatusCode::kInternal, "oh no!"));
        ASSERT_STATUS_OK(status_or);
      },
      "Status of \"status_or\" is expected to be OK, but evaluates to \"oh "
      "no!\" (code INTERNAL)");
}

TEST(AssertOkTest, AssertionFailedDescription) {
  EXPECT_FATAL_FAILURE(
      {
        Status status(StatusCode::kInternal, "oh no!");
        ASSERT_STATUS_OK(status) << "my precious assertion failed";
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)\nmy precious assertion failed");
}

TEST(AssertOkTest, AssertionFailedDescriptionStatusOr) {
  EXPECT_FATAL_FAILURE(
      {
        StatusOr<int> status_or(Status(StatusCode::kInternal, "oh no!"));
        ASSERT_STATUS_OK(status_or) << "my precious assertion failed";
      },
      "Status of \"status_or\" is expected to be OK, but evaluates to \"oh "
      "no!\" "
      "(code INTERNAL)\nmy precious assertion failed");
}

TEST(ExpectOkTest, ExpectOk) {
  Status status;
  EXPECT_STATUS_OK(status);
}

TEST(ExpectOkTest, ExpectOkStatusOr) {
  StatusOr<int> status_or(42);
  EXPECT_STATUS_OK(status_or);
}

TEST(ExpectOkTest, ExpectionOkDescription) {
  Status status;
  EXPECT_STATUS_OK(status) << "OK is not OK?";
}

TEST(ExpectOkTest, ExpectionOkDescriptionStatusOr) {
  StatusOr<int> status_or(42);
  EXPECT_STATUS_OK(status_or) << "OK is not OK?";
}

TEST(ExpectOkTest, ExpectionFailed) {
  EXPECT_NONFATAL_FAILURE(
      {
        Status status(StatusCode::kInternal, "oh no!");
        EXPECT_STATUS_OK(status);
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)");
}

TEST(ExpectOkTest, ExpectionFailedStatusOr) {
  EXPECT_NONFATAL_FAILURE(
      {
        StatusOr<int> status_or(Status(StatusCode::kInternal, "oh no!"));
        EXPECT_STATUS_OK(status_or);
      },
      "Status of \"status_or\" is expected to be OK, but evaluates to \"oh "
      "no!\" "
      "(code INTERNAL)");
}

TEST(ExpectOkTest, ExpectionFailedDescription) {
  EXPECT_NONFATAL_FAILURE(
      {
        Status status(StatusCode::kInternal, "oh no!");
        EXPECT_STATUS_OK(status) << "my precious assertion failed";
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)\nmy precious assertion failed");
}

TEST(ExpectOkTest, ExpectionFailedDescriptionStatusOr) {
  EXPECT_NONFATAL_FAILURE(
      {
        StatusOr<int> status_or(Status(StatusCode::kInternal, "oh no!"));
        EXPECT_STATUS_OK(status_or) << "my precious assertion failed";
      },
      "Status of \"status_or\" is expected to be OK, but evaluates to \"oh "
      "no!\" (code INTERNAL)\nmy precious assertion failed");
}

TEST(GrpcStatusTest, AssertionOk) {
  ::grpc::Status status;
  ASSERT_STATUS_OK(status);
}

TEST(GrpcStatusTest, AssertionOkDescription) {
  ::grpc::Status status;
  ASSERT_STATUS_OK(status) << "OK is not OK?";
}

TEST(GrpcStatusTest, AssertionFailed) {
  EXPECT_FATAL_FAILURE(
      {
        ::grpc::Status status(::grpc::StatusCode::INTERNAL, "oh no!");
        ASSERT_STATUS_OK(status);
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)");
}

TEST(GrpcStatusTest, AssertionFailedDescription) {
  EXPECT_FATAL_FAILURE(
      {
        ::grpc::Status status(::grpc::StatusCode::INTERNAL, "oh no!");
        ASSERT_STATUS_OK(status) << "my precious assertion failed";
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)\nmy precious assertion failed");
}

TEST(GrpcStatusTest, ExpectOk) {
  ::grpc::Status status;
  EXPECT_STATUS_OK(status);
}

TEST(GrpcStatusTest, ExpectionOkDescription) {
  ::grpc::Status status;
  EXPECT_STATUS_OK(status) << "OK is not OK?";
}

TEST(GrpcStatusTest, ExpectionFailed) {
  EXPECT_NONFATAL_FAILURE(
      {
        ::grpc::Status status(::grpc::StatusCode::INTERNAL, "oh no!");
        EXPECT_STATUS_OK(status);
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)");
}

TEST(GrpcStatusTest, ExpectionFailedDescription) {
  EXPECT_NONFATAL_FAILURE(
      {
        ::grpc::Status status(::grpc::StatusCode::INTERNAL, "oh no!");
        EXPECT_STATUS_OK(status) << "my precious assertion failed";
      },
      "Status of \"status\" is expected to be OK, but evaluates to \"oh no!\" "
      "(code INTERNAL)\nmy precious assertion failed");
}
