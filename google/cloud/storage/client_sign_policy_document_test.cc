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
#include "google/cloud/storage/oauth2/google_application_default_credentials_file.h"
#include "google/cloud/storage/oauth2/google_credentials.h"
#include "google/cloud/storage/testing/constants.h"
#include "google/cloud/storage/testing/mock_client.h"
#include "google/cloud/storage/testing/retry_tests.h"
#include "google/cloud/internal/format_time_point.h"
#include "google/cloud/internal/setenv.h"
#include "google/cloud/testing_util/assert_ok.h"
#include <gmock/gmock.h>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace {

using ::google::cloud::storage::testing::Dec64;
using ::google::cloud::storage::testing::kJsonKeyfileContents;
using ::google::cloud::storage::testing::canonical_errors::TransientError;
using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::ReturnRef;

/**
 * Test the CreateSignedPolicyDocument function in storage::Client.
 */
class CreateSignedPolicyDocTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto creds = oauth2::CreateServiceAccountCredentialsFromJsonContents(
        kJsonKeyfileContents);
    ASSERT_STATUS_OK(creds);
    client_.reset(new Client(*creds));
  }

  std::unique_ptr<Client> client_;
};

/**
 * Test the RPCs in CreateSignedPolicyDocument function in storage::Client.
 */
class CreateSignedPolicyDocRPCTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_ = std::make_shared<testing::MockClient>();
    EXPECT_CALL(*mock_, client_options())
        .WillRepeatedly(ReturnRef(client_options_));
    client_.reset(new Client{
        std::static_pointer_cast<internal::RawClient>(mock_),
        ExponentialBackoffPolicy(std::chrono::milliseconds(1),
                                 std::chrono::milliseconds(1), 2.0)});
  }
  void TearDown() override {
    client_.reset();
    mock_.reset();
  }

  std::shared_ptr<testing::MockClient> mock_;
  std::unique_ptr<Client> client_;
  ClientOptions client_options_ =
      ClientOptions(oauth2::CreateAnonymousCredentials());
};

PolicyDocument CreatePolicyDocumentForTest() {
  PolicyDocument result;
  result.expiration =
      google::cloud::internal::ParseRfc3339("2010-06-16T11:11:11Z");
  result.conditions.emplace_back(
      PolicyDocumentCondition::StartsWith("key", ""));
  result.conditions.emplace_back(
      PolicyDocumentCondition::ExactMatchObject("acl", "bucket-owner-read"));
  result.conditions.emplace_back(
      PolicyDocumentCondition::ExactMatchObject("bucket", "travel-maps"));
  result.conditions.emplace_back(
      PolicyDocumentCondition::ExactMatch("Content-Type", "image/jpeg"));
  result.conditions.emplace_back(
      PolicyDocumentCondition::ContentLengthRange(0, 1000000));
  return result;
}

TEST_F(CreateSignedPolicyDocTest, Sign) {
  auto actual =
      client_->CreateSignedPolicyDocument(CreatePolicyDocumentForTest());
  ASSERT_STATUS_OK(actual);

  EXPECT_EQ("foo-email@foo-project.iam.gserviceaccount.com", actual->access_id);

  EXPECT_EQ("2010-06-16T11:11:11Z",
            google::cloud::internal::FormatRfc3339(actual->expiration));

  EXPECT_EQ(
      "{"
      "\"conditions\":["
      "[\"starts-with\",\"$key\",\"\"],"
      "{\"acl\":\"bucket-owner-read\"},"
      "{\"bucket\":\"travel-maps\"},"
      "[\"eq\",\"$Content-Type\",\"image/jpeg\"],"
      "[\"content-length-range\",0,1000000]"
      "],"
      "\"expiration\":\"2010-06-16T11:11:11Z\"}",
      Dec64(actual->policy));

  EXPECT_EQ(
      "QoQzyjIedQkiLydcnBvZMvXRlF5yGWgHaEahybtNOZErr6tDqB7pyUCFcGM8aiukSDYVi/"
      "vxQ5YR3YjjTt9khphFOBqBRO5z6/HdX1i9QUGAd3MsTRe9Atlfwx9fj+7sz87Hebv9lJN/"
      "VLRJv7nMuVqGY+QVaXk3krPQNSWJ1cxo+Ip/M7SPP/iFH9O1CnN5QsE7lgLEH/"
      "BdMTaNoblc4XZMfgFZXtxWgi4hSsuAgbGx4ByTlU+BP1cbpfsc1A2Cu8byZtYJQ5cEp7f1+"
      "Kv2zNRqGqYrFWwDhfFHj9t3jj/DuaWycTfpCGfTtOMSB7+rEV87w/vgitFyVS+o0TrrHA==",
      actual->signature);
}

/// @test Verify that CreateSignedPolicyDocument() uses the SignBlob API when
/// needed.
TEST_F(CreateSignedPolicyDocRPCTest, SignRemote) {
  // Use `echo -n test-signed-blob | openssl base64 -e` to create the magic
  // string.
  std::string expected_signed_blob = "dGVzdC1zaWduZWQtYmxvYg==";

  EXPECT_CALL(*mock_, SignBlob(_))
      .WillOnce(Return(StatusOr<internal::SignBlobResponse>(TransientError())))
      .WillOnce([&expected_signed_blob](internal::SignBlobRequest const&) {
        return make_status_or(
            internal::SignBlobResponse{"test-key-id", expected_signed_blob});
      });
  auto actual =
      client_->CreateSignedPolicyDocument(CreatePolicyDocumentForTest());
  ASSERT_STATUS_OK(actual);
  EXPECT_THAT(actual->signature, expected_signed_blob);
}

/// @test Verify that CreateSignedPolicyDocument() + SignBlob() respects retry
/// policies.
TEST_F(CreateSignedPolicyDocRPCTest, SignPolicyTooManyFailures) {
  testing::TooManyFailuresStatusTest<internal::SignBlobResponse>(
      mock_, EXPECT_CALL(*mock_, SignBlob(_)),
      [](Client& client) {
        return client.CreateSignedPolicyDocument(CreatePolicyDocumentForTest())
            .status();
      },
      "SignBlob");
}

/// @test Verify that CreateSignedPolicyDocument() + SignBlob() respects retry
/// policies.
TEST_F(CreateSignedPolicyDocRPCTest, SignPolicyPermanentFailure) {
  testing::PermanentFailureStatusTest<internal::SignBlobResponse>(
      *client_, EXPECT_CALL(*mock_, SignBlob(_)),
      [](Client& client) {
        return client.CreateSignedPolicyDocument(CreatePolicyDocumentForTest())
            .status();
      },
      "SignBlob");
}

PolicyDocumentV4 CreatePolicyDocumentV4ForTest() {
  PolicyDocumentV4 result;
  result.bucket = "test-bucket";
  result.object = "test-object";
  result.expiration = std::chrono::seconds(13);
  result.timestamp =
      google::cloud::internal::ParseRfc3339("2010-06-16T11:11:11Z");
  result.conditions.emplace_back(
      PolicyDocumentCondition::StartsWith("Content-Type", "image/"));
  result.conditions.emplace_back(
      PolicyDocumentCondition::ExactMatchObject("bucket", "travel-maps"));
  result.conditions.emplace_back(
      PolicyDocumentCondition::ExactMatch("Content-Disposition", "inline"));
  result.conditions.emplace_back(
      PolicyDocumentCondition::ContentLengthRange(0, 1000000));
  return result;
}

TEST_F(CreateSignedPolicyDocTest, SignV4) {
  auto actual = client_->GenerateSignedPostPolicyV4(
      CreatePolicyDocumentV4ForTest(), AddExtensionFieldOption(),
      PredefinedAcl(), Scheme());
  ASSERT_STATUS_OK(actual);

  EXPECT_EQ("https://storage.googleapis.com/test-bucket/", actual->url);
  EXPECT_EQ(
      "foo-email@foo-project.iam.gserviceaccount.com/20100616/auto/storage/"
      "goog4_request",
      actual->access_id);
  EXPECT_EQ("2010-06-16T11:11:24Z",
            google::cloud::internal::FormatRfc3339(actual->expiration));

  EXPECT_EQ(
      "{"
      "\"conditions\":["
      "[\"starts-with\",\"$Content-Type\",\"image/\"],"
      "{\"bucket\":\"travel-maps\"},"
      "[\"eq\",\"$Content-Disposition\",\"inline\"],"
      "[\"content-length-range\",0,1000000],"
      "{\"bucket\":\"test-bucket\"},"
      "{\"key\":\"test-object\"},"
      "{\"x-goog-date\":\"20100616T111111Z\"},"
      "{\"x-goog-credential\":\"foo-email@foo-project.iam.gserviceaccount.com/"
      "20100616/auto/storage/goog4_request\"},"
      "{\"x-goog-algorithm\":\"GOOG4-RSA-SHA256\"}"
      "],"
      "\"expiration\":\"2010-06-16T11:11:24Z\"}",
      Dec64(actual->policy));

  EXPECT_EQ(
      "25b5ef60e9d80fc94ac8c0d94bb8533b6d59de07371091ecf3f698cf465c8d54240a60bf"
      "39840c3e1133d3d07345842809ee97e809a73a801b20ad1a6bcb4d2fb8dfd796b99a85c5"
      "8dde9f76f28d4724543bad012b6f69fd822179c338852d717272313456b895ca95303ced"
      "6fbdee01e23f983df8a594b23a6977b24ff5027a3b491ef2c54fb008cac1eccec15da422"
      "fb6422722edad8e4208e82f8bee82e095441b22a721b8a1d64139958d3fa91739244b203"
      "62998a73258afc68b1bf7bdb9cbeec392829a401e186ec6fb810f647b502005b1742d333"
      "421393b555fc1446f5c6e2b715054f1dd6abbc21b5aade89f17de8edcbae9720bc4bfcb7"
      "ace38d22",
      actual->signature);

  EXPECT_EQ("GOOG4-RSA-SHA256", actual->signing_algorithm);
}

TEST_F(CreateSignedPolicyDocTest, SignV4AddExtensionField) {
  auto actual = client_->GenerateSignedPostPolicyV4(
      CreatePolicyDocumentV4ForTest(),
      AddExtensionField("my-field", "my-value"));
  ASSERT_STATUS_OK(actual);

  EXPECT_THAT(Dec64(actual->policy), HasSubstr("{\"my-field\":\"my-value\"}"));
}

TEST_F(CreateSignedPolicyDocTest, SignV4PredefinedAcl) {
  auto actual = client_->GenerateSignedPostPolicyV4(
      CreatePolicyDocumentV4ForTest(), PredefinedAcl::BucketOwnerRead());
  ASSERT_STATUS_OK(actual);

  EXPECT_THAT(Dec64(actual->policy),
              HasSubstr("{\"acl\":\"bucket-owner-read\"}"));
}

TEST_F(CreateSignedPolicyDocTest, SignV4BucketBoundHostname) {
  auto actual = client_->GenerateSignedPostPolicyV4(
      CreatePolicyDocumentV4ForTest(), BucketBoundHostname("mydomain.tld"));
  ASSERT_STATUS_OK(actual);

  EXPECT_EQ("https://mydomain.tld/", actual->url);
}

TEST_F(CreateSignedPolicyDocTest, SignV4BucketBoundHostnameHTTP) {
  auto actual = client_->GenerateSignedPostPolicyV4(
      CreatePolicyDocumentV4ForTest(), BucketBoundHostname("mydomain.tld"),
      Scheme("http"));
  ASSERT_STATUS_OK(actual);

  EXPECT_EQ("http://mydomain.tld/", actual->url);
}

TEST_F(CreateSignedPolicyDocTest, SignV4VirtualHostname) {
  auto actual = client_->GenerateSignedPostPolicyV4(
      CreatePolicyDocumentV4ForTest(), VirtualHostname(true));
  ASSERT_STATUS_OK(actual);

  EXPECT_EQ("https://test-bucket.storage.googleapis.com/", actual->url);
}

}  // namespace
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
