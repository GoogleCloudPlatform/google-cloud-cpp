#!/usr/bin/env bash
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Common configuration parameters.
#
export GOOGLE_CLOUD_PROJECT="cloud-cpp-testing-resources"

# Cloud Bigtable configuration parameters
export GOOGLE_CLOUD_CPP_BIGTABLE_TEST_INSTANCE_ID="test-instance"
export GOOGLE_CLOUD_CPP_BIGTABLE_TEST_ZONE_A="us-west2-b"
export GOOGLE_CLOUD_CPP_BIGTABLE_TEST_ZONE_B="us-west2-c"
export GOOGLE_CLOUD_CPP_BIGTABLE_TEST_SERVICE_ACCOUNT="bigtable-test-iam-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"

# Cloud Storage configuration parameters
export GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME="cloud-cpp-testing-bucket"
export GOOGLE_CLOUD_CPP_STORAGE_TEST_DESTINATION_BUCKET_NAME="cloud-cpp-testing-regional"
export GOOGLE_CLOUD_CPP_STORAGE_TEST_REGION_ID="us-central1"
export GOOGLE_CLOUD_CPP_STORAGE_TEST_LOCATION="${GOOGLE_CLOUD_CPP_STORAGE_TEST_REGION_ID}"
export GOOGLE_CLOUD_CPP_STORAGE_TEST_SERVICE_ACCOUNT="storage-test-iam-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
export GOOGLE_CLOUD_CPP_STORAGE_TEST_SIGNING_SERVICE_ACCOUNT="kokoro-agent@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
export GOOGLE_CLOUD_CPP_STORAGE_TEST_CMEK_KEY="projects/${GOOGLE_CLOUD_PROJECT}/locations/us/keyRings/gcs-testing-us-kr/cryptoKeys/integration-tests-key"
export GOOGLE_CLOUD_CPP_STORAGE_TEST_TOPIC_NAME="projects/${GOOGLE_CLOUD_PROJECT}/topics/gcs-changes"

# Cloud Spanner configuration parameters
export GOOGLE_CLOUD_CPP_SPANNER_TEST_INSTANCE_ID="test-instance"
export GOOGLE_CLOUD_CPP_SPANNER_TEST_SERVICE_ACCOUNT="spanner-iam-test-sa@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"

# Cloud Pub/Sub only needs GOOGLE_CLOUD_PROJECT


#
# TODO(#3523 #3524) - remove these legacy variables
#

export PROJECT_ID=${GOOGLE_CLOUD_PROJECT}

export INSTANCE_ID=${GOOGLE_CLOUD_CPP_BIGTABLE_TEST_INSTANCE_ID}
export ZONE_A=${GOOGLE_CLOUD_CPP_BIGTABLE_TEST_ZONE_A}
export ZONE_B=${GOOGLE_CLOUD_CPP_BIGTABLE_TEST_ZONE_B}

export BUCKET_NAME="${GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME}"
export DESTINATION_BUCKET_NAME="${GOOGLE_CLOUD_CPP_STORAGE_TEST_DESTINATION_BUCKET_NAME}"
export STORAGE_REGION_ID="${GOOGLE_CLOUD_CPP_STORAGE_TEST_REGION_ID}"
export LOCATION=${STORAGE_REGION_ID}
export SERVICE_ACCOUNT="${GOOGLE_CLOUD_CPP_STORAGE_TEST_SERVICE_ACCOUNT}"
export SIGNING_SERVICE_ACCOUNT="${GOOGLE_CLOUD_CPP_STORAGE_TEST_SIGNING_SERVICE_ACCOUNT}"
export STORAGE_CMEK_KEY="${GOOGLE_CLOUD_CPP_STORAGE_TEST_CMEK_KEY}"
export TOPIC_NAME="${GOOGLE_CLOUD_CPP_STORAGE_TEST_TOPIC_NAME}"

export GOOGLE_CLOUD_CPP_SPANNER_INSTANCE="${GOOGLE_CLOUD_CPP_SPANNER_TEST_INSTANCE_ID}"
export GOOGLE_CLOUD_CPP_SPANNER_IAM_TEST_SA="${GOOGLE_CLOUD_CPP_SPANNER_TEST_SERVICE_ACCOUNT}"
