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

#include "google/cloud/storage/benchmarks/throughput_experiment.h"
#include "google/cloud/storage/testing/storage_integration_test.h"
#include "google/cloud/internal/getenv.h"
#include "google/cloud/testing_util/assert_ok.h"
#include <gmock/gmock.h>

namespace google {
namespace cloud {
namespace storage_benchmarks {
namespace {

class ThroughputExperimentIntegrationTest
    : public google::cloud::storage::testing::StorageIntegrationTest,
      public ::testing::WithParamInterface<ApiName> {
 protected:
  void SetUp() override {
    bucket_name_ = google::cloud::internal::GetEnv(
                       "GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME")
                       .value_or("");
    ASSERT_FALSE(bucket_name_.empty());
  }

  std::string bucket_name_;
};

TEST_P(ThroughputExperimentIntegrationTest, Upload) {
  auto client = MakeIntegrationTestClient();
  ASSERT_STATUS_OK(client);

  ThroughputOptions options;
  options.minimum_write_size = 1 * kMiB;
  options.enabled_apis = {GetParam()};

  auto const& client_options = client->raw_client()->client_options();
  auto experiments = CreateUploadExperiments(options, client_options);
  for (auto& e : experiments) {
    auto object_name = MakeRandomObjectName();
    ThroughputExperimentConfig config{OpType::kOpInsert,
                                      16 * kKiB,
                                      1 * kMiB,
                                      client_options.upload_buffer_size(),
                                      /*enable_crc32c=*/false,
                                      /*enable_md5=*/false};
    auto result = e->Run(bucket_name_, object_name, config);
    EXPECT_EQ(result.status, StatusCode::kOk);
    if (result.status == StatusCode::kOk) {
      auto status = client->DeleteObject(bucket_name_, object_name);
      EXPECT_STATUS_OK(status);
    }
  }
}

TEST_P(ThroughputExperimentIntegrationTest, Download) {
  auto client = MakeIntegrationTestClient();
  ASSERT_STATUS_OK(client);

  ThroughputOptions options;
  options.minimum_write_size = 1 * kMiB;
  options.enabled_apis = {GetParam()};

  auto const& client_options = client->raw_client()->client_options();
  auto experiments = CreateUploadExperiments(options, client_options);
  for (auto& e : experiments) {
    auto object_name = MakeRandomObjectName();

    ThroughputExperimentConfig config{OpType::kOpRead0,
                                      16 * kKiB,
                                      1 * kMiB,
                                      client_options.upload_buffer_size(),
                                      /*enable_crc32c=*/false,
                                      /*enable_md5=*/false};

    auto contents = MakeRandomData(config.object_size);
    auto insert =
        client->InsertObject(bucket_name_, object_name, std::move(contents));
    ASSERT_STATUS_OK(insert);

    auto result = e->Run(bucket_name_, object_name, config);
    EXPECT_EQ(result.status, StatusCode::kOk);
    if (result.status == StatusCode::kOk) {
      auto status = client->DeleteObject(bucket_name_, object_name);
      EXPECT_STATUS_OK(status);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(ThroughputExperimentIntegrationTestJson,
                         ThroughputExperimentIntegrationTest,
                         ::testing::Values(ApiName::kApiJson));
INSTANTIATE_TEST_SUITE_P(ThroughputExperimentIntegrationTestXml,
                         ThroughputExperimentIntegrationTest,
                         ::testing::Values(ApiName::kApiXml));
INSTANTIATE_TEST_SUITE_P(ThroughputExperimentIntegrationTestGrpc,
                         ThroughputExperimentIntegrationTest,
                         ::testing::Values(ApiName::kApiGrpc));

}  // namespace
}  // namespace storage_benchmarks
}  // namespace cloud
}  // namespace google
