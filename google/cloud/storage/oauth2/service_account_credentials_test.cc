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

#include "google/cloud/storage/oauth2/service_account_credentials.h"
#include "google/cloud/storage/oauth2/credential_constants.h"
#include "google/cloud/storage/oauth2/google_credentials.h"
#include "google/cloud/storage/testing/constants.h"
#include "google/cloud/storage/testing/mock_fake_clock.h"
#include "google/cloud/storage/testing/mock_http_request.h"
#include "google/cloud/internal/random.h"
#include "google/cloud/internal/setenv.h"
#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/testing_util/status_matchers.h"
#include "absl/strings/str_split.h"
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace oauth2 {
namespace {

using ::google::cloud::storage::internal::HttpResponse;
using ::google::cloud::storage::testing::FakeClock;
using ::google::cloud::storage::testing::kAltScopeForTest;
using ::google::cloud::storage::testing::kExpectedAssertionParam;
using ::google::cloud::storage::testing::
    kExpectedAssertionWithOptionalArgsParam;
using ::google::cloud::storage::testing::kFixedJwtTimestamp;
using ::google::cloud::storage::testing::kGrantParamEscaped;
using ::google::cloud::storage::testing::kGrantParamUnescaped;
using ::google::cloud::storage::testing::kJsonKeyfileContents;
using ::google::cloud::storage::testing::kP12KeyFileContents;
using ::google::cloud::storage::testing::kP12KeyFileMissingCerts;
using ::google::cloud::storage::testing::kP12KeyFileMissingKey;
using ::google::cloud::storage::testing::kP12ServiceAccountId;
using ::google::cloud::storage::testing::kSubjectForGrant;
using ::google::cloud::storage::testing::MockHttpRequest;
using ::google::cloud::storage::testing::MockHttpRequestBuilder;
using ::google::cloud::storage::testing::WriteBase64AsBinary;
using ::google::cloud::testing_util::StatusIs;
using ::testing::_;
using ::testing::An;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::Return;
using ::testing::StartsWith;
using ::testing::StrEq;

class ServiceAccountCredentialsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    MockHttpRequestBuilder::mock_ =
        std::make_shared<MockHttpRequestBuilder::Impl>();
    FakeClock::reset_clock(kFixedJwtTimestamp);
  }
  void TearDown() override { MockHttpRequestBuilder::mock_.reset(); }

  std::string CreateRandomFileName() {
    // When running on the internal Google CI systems we cannot write to the
    // local directory, GTest has a good temporary directory in that case.
    return ::testing::TempDir() +
           google::cloud::internal::Sample(
               generator_, 8, "abcdefghijklmnopqrstuvwxyz0123456789");
  }

  google::cloud::internal::DefaultPRNG generator_ =
      google::cloud::internal::MakeDefaultPRNG();
};

void CheckInfoYieldsExpectedAssertion(ServiceAccountCredentialsInfo const& info,
                                      std::string const& assertion) {
  auto mock_request = std::make_shared<MockHttpRequest::Impl>();
  std::string response = R"""({
      "token_type": "Type",
      "access_token": "access-token-value",
      "expires_in": 1234
  })""";
  EXPECT_CALL(*mock_request, MakeRequest(_))
      .WillOnce([response, assertion](std::string const& payload) {
        EXPECT_THAT(payload, HasSubstr(assertion));
        // Hard-coded in this order in ServiceAccountCredentials class.
        EXPECT_THAT(payload,
                    HasSubstr(std::string("grant_type=") + kGrantParamEscaped));
        return HttpResponse{200, response, {}};
      });

  auto mock_builder = MockHttpRequestBuilder::mock_;
  EXPECT_CALL(*mock_builder, BuildRequest()).WillOnce([mock_request] {
    MockHttpRequest result;
    result.mock = mock_request;
    return result;
  });

  std::string expected_header =
      "Content-Type: application/x-www-form-urlencoded";
  EXPECT_CALL(*mock_builder, AddHeader(StrEq(expected_header)));
  EXPECT_CALL(*mock_builder, Constructor(GoogleOAuthRefreshEndpoint()))
      .Times(1);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly([](std::string const& s) -> std::unique_ptr<char[]> {
        EXPECT_EQ(kGrantParamUnescaped, s);
        auto t = std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
        std::copy(kGrantParamEscaped,
                  kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
        return t;
      });

  ServiceAccountCredentials<MockHttpRequestBuilder, FakeClock> credentials(
      info);
  // Calls Refresh to obtain the access token for our authorization header.
  EXPECT_EQ("Authorization: Type access-token-value",
            credentials.AuthorizationHeader().value());
}

/// @test Verify that we can create service account credentials from a keyfile.
TEST_F(ServiceAccountCredentialsTest,
       RefreshingSendsCorrectRequestBodyAndParsesResponse) {
  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  CheckInfoYieldsExpectedAssertion(*info, kExpectedAssertionParam);
}

/// @test Verify that we can create service account credentials from a keyfile.
TEST_F(ServiceAccountCredentialsTest,
       RefreshingSendsCorrectRequestBodyAndParsesResponseForNonDefaultVals) {
  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  info->scopes = {kAltScopeForTest};
  info->subject = std::string(kSubjectForGrant);
  CheckInfoYieldsExpectedAssertion(*info,
                                   kExpectedAssertionWithOptionalArgsParam);
}

/// @test Verify that we refresh service account credentials appropriately.
TEST_F(ServiceAccountCredentialsTest,
       RefreshCalledOnlyWhenAccessTokenIsMissingOrInvalid) {
  // Prepare two responses, the first one is used but becomes immediately
  // expired, resulting in another refresh next time the caller tries to get
  // an authorization header.
  std::string r1 = R"""({
    "token_type": "Type",
    "access_token": "access-token-r1",
    "expires_in": 0
})""";
  std::string r2 = R"""({
    "token_type": "Type",
    "access_token": "access-token-r2",
    "expires_in": 1000
})""";
  auto mock_request = std::make_shared<MockHttpRequest::Impl>();
  EXPECT_CALL(*mock_request, MakeRequest(_))
      .WillOnce(Return(HttpResponse{200, r1, {}}))
      .WillOnce(Return(HttpResponse{200, r2, {}}));

  // Now setup the builder to return those responses.
  auto mock_builder = MockHttpRequestBuilder::mock_;
  EXPECT_CALL(*mock_builder, BuildRequest()).WillOnce([mock_request] {
    MockHttpRequest request;
    request.mock = mock_request;
    return request;
  });
  EXPECT_CALL(*mock_builder, AddHeader(An<std::string const&>())).Times(1);
  EXPECT_CALL(*mock_builder, Constructor(GoogleOAuthRefreshEndpoint()))
      .Times(1);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly([](std::string const& s) -> std::unique_ptr<char[]> {
        EXPECT_EQ(kGrantParamUnescaped, s);
        auto t = std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
        std::copy(kGrantParamEscaped,
                  kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
        return t;
      });

  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  ServiceAccountCredentials<MockHttpRequestBuilder> credentials(*info);
  // Calls Refresh to obtain the access token for our authorization header.
  EXPECT_EQ("Authorization: Type access-token-r1",
            credentials.AuthorizationHeader().value());
  // Token is expired, resulting in another call to Refresh.
  EXPECT_EQ("Authorization: Type access-token-r2",
            credentials.AuthorizationHeader().value());
  // Token still valid; should return cached token instead of calling Refresh.
  EXPECT_EQ("Authorization: Type access-token-r2",
            credentials.AuthorizationHeader().value());
}

/// @test Verify that `nlohmann::json::parse()` failures are reported as
/// is_discarded.
TEST_F(ServiceAccountCredentialsTest, JsonParsingFailure) {
  std::string config = R"""( not-a-valid-json-string )""";
  // The documentation for `nlohmann::json::parse()` is a bit ambiguous, so
  // wrote a little test to verify it works as I expected.
  auto parsed = nlohmann::json::parse(config, nullptr, false);
  EXPECT_TRUE(parsed.is_discarded());
  EXPECT_FALSE(parsed.is_null());
}

/// @test Verify that parsing a service account JSON string works.
TEST_F(ServiceAccountCredentialsTest, ParseSimple) {
  std::string contents = R"""({
      "type": "service_account",
      "private_key_id": "not-a-key-id-just-for-testing",
      "private_key": "not-a-valid-key-just-for-testing",
      "client_email": "test-only@test-group.example.com",
      "token_uri": "https://oauth2.googleapis.com/test_endpoint"
})""";

  auto actual =
      ParseServiceAccountCredentials(contents, "test-data", "unused-uri");
  ASSERT_STATUS_OK(actual);
  EXPECT_EQ("not-a-key-id-just-for-testing", actual->private_key_id);
  EXPECT_EQ("not-a-valid-key-just-for-testing", actual->private_key);
  EXPECT_EQ("test-only@test-group.example.com", actual->client_email);
  EXPECT_EQ("https://oauth2.googleapis.com/test_endpoint", actual->token_uri);
}

/// @test Verify that parsing a service account JSON string works.
TEST_F(ServiceAccountCredentialsTest, ParseUsesExplicitDefaultTokenUri) {
  // No token_uri attribute here, so the default passed below should be used.
  std::string contents = R"""({
      "type": "service_account",
      "private_key_id": "not-a-key-id-just-for-testing",
      "private_key": "not-a-valid-key-just-for-testing",
      "client_email": "test-only@test-group.example.com"
})""";

  auto actual = ParseServiceAccountCredentials(
      contents, "test-data", "https://oauth2.googleapis.com/test_endpoint");
  ASSERT_STATUS_OK(actual);
  EXPECT_EQ("not-a-key-id-just-for-testing", actual->private_key_id);
  EXPECT_EQ("not-a-valid-key-just-for-testing", actual->private_key);
  EXPECT_EQ("test-only@test-group.example.com", actual->client_email);
  EXPECT_EQ("https://oauth2.googleapis.com/test_endpoint", actual->token_uri);
}

/// @test Verify that parsing a service account JSON string works.
TEST_F(ServiceAccountCredentialsTest, ParseUsesImplicitDefaultTokenUri) {
  // No token_uri attribute here.
  std::string contents = R"""({
      "type": "service_account",
      "private_key_id": "not-a-key-id-just-for-testing",
      "private_key": "not-a-valid-key-just-for-testing",
      "client_email": "test-only@test-group.example.com"
})""";

  // No token_uri passed in here, either.
  auto actual = ParseServiceAccountCredentials(contents, "test-data");
  ASSERT_STATUS_OK(actual);
  EXPECT_EQ("not-a-key-id-just-for-testing", actual->private_key_id);
  EXPECT_EQ("not-a-valid-key-just-for-testing", actual->private_key);
  EXPECT_EQ("test-only@test-group.example.com", actual->client_email);
  EXPECT_EQ(std::string(GoogleOAuthRefreshEndpoint()), actual->token_uri);
}

/// @test Verify that invalid contents result in a readable error.
TEST_F(ServiceAccountCredentialsTest, ParseInvalidContentsFails) {
  std::string config = R"""( not-a-valid-json-string )""";

  auto actual = ParseServiceAccountCredentials(config, "test-as-a-source");
  EXPECT_THAT(actual,
              StatusIs(Not(StatusCode::kOk),
                       AllOf(HasSubstr("Invalid ServiceAccountCredentials"),
                             HasSubstr("test-as-a-source"))));
}

/// @test Parsing a service account JSON string should detect empty fields.
TEST_F(ServiceAccountCredentialsTest, ParseEmptyFieldFails) {
  std::string contents = R"""({
      "type": "service_account",
      "private_key": "not-a-valid-key-just-for-testing",
      "client_email": "test-only@test-group.example.com",
      "token_uri": "https://oauth2.googleapis.com/token"
})""";

  for (auto const& field : {"private_key", "client_email", "token_uri"}) {
    auto json = nlohmann::json::parse(contents);
    json[field] = "";
    auto actual = ParseServiceAccountCredentials(json.dump(), "test-data", "");
    EXPECT_THAT(actual,
                StatusIs(Not(StatusCode::kOk),
                         AllOf(HasSubstr(field), HasSubstr(" field is empty"),
                               HasSubstr("test-data"))));
  }
}

/// @test Parsing a service account JSON string should detect missing fields.
TEST_F(ServiceAccountCredentialsTest, ParseMissingFieldFails) {
  std::string contents = R"""({
      "type": "service_account",
      "private_key": "not-a-valid-key-just-for-testing",
      "client_email": "test-only@test-group.example.com",
      "token_uri": "https://oauth2.googleapis.com/token"
})""";

  for (auto const& field : {"private_key", "client_email"}) {
    auto json = nlohmann::json::parse(contents);
    json.erase(field);
    auto actual = ParseServiceAccountCredentials(json.dump(), "test-data", "");
    EXPECT_THAT(actual,
                StatusIs(Not(StatusCode::kOk),
                         AllOf(HasSubstr(field), HasSubstr(" field is missing"),
                               HasSubstr("test-data"))));
  }
}

/// @test Parsing a service account JSON string allows an optional field.
TEST_F(ServiceAccountCredentialsTest, ParseOptionalField) {
  std::string contents = R"""({
      "type": "service_account",
      "private_key_id": "",
      "private_key": "not-a-valid-key-just-for-testing",
      "client_email": "test-only@test-group.example.com",
      "token_uri": "https://oauth2.googleapis.com/token"
})""";

  auto json = nlohmann::json::parse(contents);
  auto actual = ParseServiceAccountCredentials(json.dump(), "test-data", "");
  ASSERT_STATUS_OK(actual.status());
}

/// @test Verify that refreshing a credential updates the timestamps.
TEST_F(ServiceAccountCredentialsTest, RefreshingUpdatesTimestamps) {
  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);

  // NOLINTNEXTLINE(google-runtime-int)
  auto make_request_assertion = [&info](long timestamp) {
    return [timestamp, &info](std::string const& p) {
      std::string const prefix =
          std::string("grant_type=") + kGrantParamEscaped + "&assertion=";
      EXPECT_THAT(p, StartsWith(prefix));

      std::string assertion = p.substr(prefix.size());

      std::vector<std::string> const tokens = absl::StrSplit(assertion, '.');
      std::string const& encoded_header = tokens[0];
      std::string const& encoded_payload = tokens[1];

      auto header_bytes = internal::UrlsafeBase64Decode(encoded_header);
      std::string header_str{header_bytes.begin(), header_bytes.end()};
      auto payload_bytes = internal::UrlsafeBase64Decode(encoded_payload);
      std::string payload_str{payload_bytes.begin(), payload_bytes.end()};

      auto header = nlohmann::json::parse(header_str);
      EXPECT_EQ("RS256", header.value("alg", ""));
      EXPECT_EQ("JWT", header.value("typ", ""));
      EXPECT_EQ(info->private_key_id, header.value("kid", ""));

      auto payload = nlohmann::json::parse(payload_str);
      EXPECT_EQ(timestamp, payload.value("iat", 0));
      EXPECT_EQ(timestamp + 3600, payload.value("exp", 0));
      EXPECT_EQ(info->client_email, payload.value("iss", ""));
      EXPECT_EQ(info->token_uri, payload.value("aud", ""));

      // Hard-coded in this order in ServiceAccountCredentials class.
      std::string token = "mock-token-value-" + std::to_string(timestamp);
      nlohmann::json response{{"token_type", "Mock-Type"},
                              {"access_token", token},
                              {"expires_in", 3600}};
      return HttpResponse{200, response.dump(), {}};
    };
  };

  // Setup the mock request / response for the first Refresh().
  auto mock_request = std::make_shared<MockHttpRequest::Impl>();
  auto const clock_value_1 = 10000;
  auto const clock_value_2 = 20000;
  EXPECT_CALL(*mock_request, MakeRequest(_))
      .WillOnce(make_request_assertion(clock_value_1))
      .WillOnce(make_request_assertion(clock_value_2));

  auto mock_builder = MockHttpRequestBuilder::mock_;
  EXPECT_CALL(*mock_builder, BuildRequest()).WillOnce([mock_request] {
    MockHttpRequest result;
    result.mock = mock_request;
    return result;
  });

  std::string expected_header =
      "Content-Type: application/x-www-form-urlencoded";
  EXPECT_CALL(*mock_builder, AddHeader(StrEq(expected_header))).Times(1);
  EXPECT_CALL(*mock_builder, Constructor(GoogleOAuthRefreshEndpoint()))
      .Times(1);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly([](std::string const& s) -> std::unique_ptr<char[]> {
        EXPECT_EQ(kGrantParamUnescaped, s);
        auto t = std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
        std::copy(kGrantParamEscaped,
                  kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
        return t;
      });

  FakeClock::now_value_ = clock_value_1;
  ServiceAccountCredentials<MockHttpRequestBuilder, FakeClock> credentials(
      *info);
  // Call Refresh to obtain the access token for our authorization header.
  auto authorization_header = credentials.AuthorizationHeader();
  ASSERT_STATUS_OK(authorization_header);
  EXPECT_EQ("Authorization: Mock-Type mock-token-value-10000",
            *authorization_header);

  // Advance the clock past the expiration time of the token and then get a
  // new header.
  FakeClock::now_value_ = clock_value_2;
  EXPECT_GT(clock_value_2 - clock_value_1, 2 * 3600);
  authorization_header = credentials.AuthorizationHeader();
  ASSERT_STATUS_OK(authorization_header);
  EXPECT_EQ("Authorization: Mock-Type mock-token-value-20000",
            *authorization_header);
}

/// @test Verify that we can create sign blobs using a service account.
TEST_F(ServiceAccountCredentialsTest, SignBlob) {
  auto mock_builder = MockHttpRequestBuilder::mock_;
  std::string expected_header =
      "Content-Type: application/x-www-form-urlencoded";
  EXPECT_CALL(*mock_builder, AddHeader(StrEq(expected_header)));
  EXPECT_CALL(*mock_builder, Constructor(GoogleOAuthRefreshEndpoint()))
      .Times(1);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly([](std::string const& s) -> std::unique_ptr<char[]> {
        EXPECT_EQ(kGrantParamUnescaped, s);
        auto t = std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
        std::copy(kGrantParamEscaped,
                  kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
        return t;
      });
  EXPECT_CALL(*mock_builder, BuildRequest()).WillOnce([] {
    return MockHttpRequest();
  });

  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  ServiceAccountCredentials<MockHttpRequestBuilder, FakeClock> credentials(
      *info);

  std::string blob = R"""(GET
rmYdCNHKFXam78uCt7xQLw==
text/plain
1388534400
x-goog-encryption-algorithm:AES256
x-goog-meta-foo:bar,baz
/bucket/objectname)""";

  auto actual = credentials.SignBlob(SigningAccount(), blob);
  ASSERT_STATUS_OK(actual);

  // To generate the expected output I used:
  //   `openssl dgst -sha256 -sign private.pem blob.txt | openssl base64 -A`
  // where `blob.txt` contains the `blob` string, and `private.pem` contains
  // the private key embedded in `kJsonKeyfileContents`.
  std::string expected_signed =
      "Zsy8o5ci07DQTvO/"
      "SVr47PKsCXvN+"
      "FzXga0iYrReAnngdZYewHdcAnMQ8bZvFlTM8HY3msrRw64Jc6hoXVL979An5ugXoZ1ol/"
      "DT1KlKp3l9E0JSIbqL88ogpElTxFvgPHOtHOUsy2mzhqOVrNSXSj4EM50gKHhvHKSbFq8Pcj"
      "lAkROtq5gqp5t0OFd7EMIaRH+tekVUZjQPfFT/"
      "hRW9bSCCV8w1Ex+"
      "QxmB5z7P7zZn2pl7JAcL850emTo8f2tfv1xXWQGhACvIJeMdPmyjbc04Ye4M8Ljpkg3YhE6l"
      "4GwC2MnI8TkuoHe4Bj2MvA8mM8TVwIvpBs6Etsj6Jdaz4rg==";
  EXPECT_EQ(expected_signed, internal::Base64Encode(*actual));
}

/// @test Verify that signing blobs fails with invalid e-mail.
TEST_F(ServiceAccountCredentialsTest, SignBlobFailure) {
  auto mock_builder = MockHttpRequestBuilder::mock_;
  std::string expected_header =
      "Content-Type: application/x-www-form-urlencoded";
  EXPECT_CALL(*mock_builder, AddHeader(StrEq(expected_header)));
  EXPECT_CALL(*mock_builder, Constructor(GoogleOAuthRefreshEndpoint()))
      .Times(1);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly([](std::string const& s) -> std::unique_ptr<char[]> {
        EXPECT_EQ(kGrantParamUnescaped, s);
        auto t = std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
        std::copy(kGrantParamEscaped,
                  kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
        return t;
      });
  EXPECT_CALL(*mock_builder, BuildRequest()).WillOnce([] {
    return MockHttpRequest();
  });

  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  ServiceAccountCredentials<MockHttpRequestBuilder, FakeClock> credentials(
      *info);

  auto actual =
      credentials.SignBlob(SigningAccount("fake@fake.com"), "test-blob");
  EXPECT_THAT(
      actual,
      StatusIs(StatusCode::kInvalidArgument,
               HasSubstr("The current_credentials cannot sign blobs for ")));
}

/// @test Verify that we can get the client id from a service account.
TEST_F(ServiceAccountCredentialsTest, ClientId) {
  auto mock_builder = MockHttpRequestBuilder::mock_;
  std::string expected_header =
      "Content-Type: application/x-www-form-urlencoded";
  EXPECT_CALL(*mock_builder, AddHeader(StrEq(expected_header)));
  EXPECT_CALL(*mock_builder, Constructor(GoogleOAuthRefreshEndpoint()))
      .Times(1);
  EXPECT_CALL(*mock_builder, MakeEscapedString(An<std::string const&>()))
      .WillRepeatedly([](std::string const& s) -> std::unique_ptr<char[]> {
        EXPECT_EQ(kGrantParamUnescaped, s);
        auto t = std::unique_ptr<char[]>(new char[sizeof(kGrantParamEscaped)]);
        std::copy(kGrantParamEscaped,
                  kGrantParamEscaped + sizeof(kGrantParamEscaped), t.get());
        return t;
      });
  EXPECT_CALL(*mock_builder, BuildRequest()).WillOnce([] {
    return MockHttpRequest();
  });

  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  ServiceAccountCredentials<MockHttpRequestBuilder, FakeClock> credentials(
      *info);

  EXPECT_EQ("foo-email@foo-project.iam.gserviceaccount.com",
            credentials.AccountEmail());
  EXPECT_EQ("a1a111aa1111a11a11a11aa111a111a1a1111111", credentials.KeyId());
}

/// @test Verify that parsing a service account JSON string works.
TEST_F(ServiceAccountCredentialsTest, ParseSimpleP12) {
  auto filename = CreateRandomFileName() + ".p12";
  WriteBase64AsBinary(filename, kP12KeyFileContents);

  auto info = ParseServiceAccountP12File(filename);
  ASSERT_STATUS_OK(info);

  EXPECT_EQ(kP12ServiceAccountId, info->client_email);
  EXPECT_FALSE(info->private_key.empty());
  EXPECT_EQ(0, std::remove(filename.c_str()));

  ServiceAccountCredentials<> credentials(*info);

  auto signed_blob = credentials.SignBlob(SigningAccount(), "test-blob");
  EXPECT_STATUS_OK(signed_blob);
}

TEST_F(ServiceAccountCredentialsTest, ParseP12MissingKey) {
  std::string filename = CreateRandomFileName() + ".p12";
  WriteBase64AsBinary(filename, kP12KeyFileMissingKey);
  auto info = ParseServiceAccountP12File(filename);
  EXPECT_FALSE(info.ok());
}

TEST_F(ServiceAccountCredentialsTest, ParseP12MissingCerts) {
  std::string filename = ::testing::TempDir() + CreateRandomFileName() + ".p12";
  WriteBase64AsBinary(filename, kP12KeyFileMissingCerts);
  auto info = ParseServiceAccountP12File(filename);
  EXPECT_FALSE(info.ok());
}

TEST_F(ServiceAccountCredentialsTest, CreateFromP12MissingFile) {
  std::string filename = CreateRandomFileName();
  // Loading a non-existent file should fail.
  auto actual = CreateServiceAccountCredentialsFromP12FilePath(filename);
  EXPECT_FALSE(actual.ok());
}

TEST_F(ServiceAccountCredentialsTest, CreateFromP12EmptyFile) {
  std::string filename = CreateRandomFileName();
  std::ofstream(filename).close();

  // Loading an empty file should fail.
  auto actual = CreateServiceAccountCredentialsFromP12FilePath(filename);
  EXPECT_FALSE(actual.ok());

  EXPECT_EQ(0, std::remove(filename.c_str()));
}

TEST_F(ServiceAccountCredentialsTest, CreateFromP12ValidFile) {
  std::string filename = CreateRandomFileName() + ".p12";
  WriteBase64AsBinary(filename, kP12KeyFileContents);

  // Loading an empty file should fail.
  auto actual = CreateServiceAccountCredentialsFromP12FilePath(filename);
  EXPECT_STATUS_OK(actual);

  EXPECT_EQ(0, std::remove(filename.c_str()));
}

/// @test Verify we can obtain JWT assertion components given the info parsed
/// from a keyfile.
TEST_F(ServiceAccountCredentialsTest, AssertionComponentsFromInfo) {
  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  auto const clock_value_1 = 10000;
  FakeClock::now_value_ = clock_value_1;
  auto components = AssertionComponentsFromInfo(*info, FakeClock::now());

  auto header = nlohmann::json::parse(components.first);
  EXPECT_EQ("RS256", header.value("alg", ""));
  EXPECT_EQ("JWT", header.value("typ", ""));
  EXPECT_EQ(info->private_key_id, header.value("kid", ""));

  auto payload = nlohmann::json::parse(components.second);
  EXPECT_EQ(clock_value_1, payload.value("iat", 0));
  EXPECT_EQ(clock_value_1 + 3600, payload.value("exp", 0));
  EXPECT_EQ(info->client_email, payload.value("iss", ""));
  EXPECT_EQ(info->token_uri, payload.value("aud", ""));
}

/// @test Verify we can construct a JWT assertion given the info parsed from a
/// keyfile.
TEST_F(ServiceAccountCredentialsTest, MakeJWTAssertion) {
  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  FakeClock::reset_clock(kFixedJwtTimestamp);
  auto components = AssertionComponentsFromInfo(*info, FakeClock::now());
  auto assertion =
      MakeJWTAssertion(components.first, components.second, info->private_key);

  std::vector<std::string> expected_tokens =
      absl::StrSplit(kExpectedAssertionParam, '.');
  std::string const& expected_encoded_header = expected_tokens[0];
  std::string const& expected_encoded_payload = expected_tokens[1];
  std::string const& expected_encoded_signature = expected_tokens[2];

  std::vector<std::string> actual_tokens = absl::StrSplit(assertion, '.');
  std::string const& actual_encoded_header = actual_tokens[0];
  std::string const& actual_encoded_payload = actual_tokens[1];
  std::string const& actual_encoded_signature = actual_tokens[2];

  EXPECT_EQ(expected_encoded_header, "assertion=" + actual_encoded_header);
  EXPECT_EQ(expected_encoded_payload, actual_encoded_payload);
  EXPECT_EQ(expected_encoded_signature, actual_encoded_signature);
}

/// @test Verify we can construct a service account refresh payload given the
/// info parsed from a keyfile.
TEST_F(ServiceAccountCredentialsTest, CreateServiceAccountRefreshPayload) {
  auto info = ParseServiceAccountCredentials(kJsonKeyfileContents, "test");
  ASSERT_STATUS_OK(info);
  FakeClock::reset_clock(kFixedJwtTimestamp);
  auto components = AssertionComponentsFromInfo(*info, FakeClock::now());
  auto assertion =
      MakeJWTAssertion(components.first, components.second, info->private_key);
  auto actual_payload = CreateServiceAccountRefreshPayload(
      *info, kGrantParamEscaped, FakeClock::now());

  EXPECT_THAT(actual_payload, HasSubstr(std::string("assertion=") + assertion));
  EXPECT_THAT(actual_payload, HasSubstr(kGrantParamEscaped));
}

/// @test Parsing a refresh response with missing fields results in failure.
TEST_F(ServiceAccountCredentialsTest,
       ParseServiceAccountRefreshResponseMissingFields) {
  std::string r1 = R"""({})""";
  // Does not have access_token.
  std::string r2 = R"""({
    "token_type": "Type",
    "id_token": "id-token-value",
    "expires_in": 1000
})""";

  FakeClock::reset_clock(1000);
  auto status = ParseServiceAccountRefreshResponse(HttpResponse{400, r1, {}},
                                                   FakeClock::now());
  EXPECT_THAT(status,
              StatusIs(StatusCode::kInvalidArgument,
                       HasSubstr("Could not find all required fields")));

  status = ParseServiceAccountRefreshResponse(HttpResponse{400, r2, {}},
                                              FakeClock::now());
  EXPECT_THAT(status,
              StatusIs(StatusCode::kInvalidArgument,
                       HasSubstr("Could not find all required fields")));
}

/// @test Parsing a refresh response yields a TemporaryToken.
TEST_F(ServiceAccountCredentialsTest, ParseServiceAccountRefreshResponse) {
  std::string r1 = R"""({
    "token_type": "Type",
    "access_token": "access-token-r1",
    "expires_in": 1000
})""";

  auto expires_in = 1000;
  FakeClock::reset_clock(2000);
  auto status = ParseServiceAccountRefreshResponse(HttpResponse{200, r1, {}},
                                                   FakeClock::now());
  EXPECT_STATUS_OK(status);
  auto token = *status;
  EXPECT_EQ(
      std::chrono::time_point_cast<std::chrono::seconds>(token.expiration_time)
          .time_since_epoch()
          .count(),
      FakeClock::now_value_ + expires_in);
  EXPECT_EQ(token.token, "Authorization: Type access-token-r1");
}

}  // namespace
}  // namespace oauth2
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
