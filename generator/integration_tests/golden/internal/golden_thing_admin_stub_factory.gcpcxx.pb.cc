// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Generated by the Codegen C++ plugin.
// If you make any local changes, they will be lost.
// source: generator/integration_tests/test.proto

#include "generator/integration_tests/golden/internal/golden_thing_admin_stub_factory.gcpcxx.pb.h"
#include "generator/integration_tests/golden/internal/golden_thing_admin_logging_decorator.gcpcxx.pb.h"
#include "generator/integration_tests/golden/internal/golden_thing_admin_metadata_decorator.gcpcxx.pb.h"
#include "generator/integration_tests/golden/internal/golden_thing_admin_stub.gcpcxx.pb.h"
#include "google/cloud/common_options.h"
#include "google/cloud/grpc_options.h"
#include "google/cloud/internal/algorithm.h"
#include "google/cloud/log.h"
#include "google/cloud/options.h"
#include <memory>

namespace google {
namespace cloud {
namespace golden_internal {
inline namespace GOOGLE_CLOUD_CPP_GENERATED_NS {

std::shared_ptr<GoldenThingAdminStub>
CreateDefaultGoldenThingAdminStub(Options const& options) {
  auto channel = grpc::CreateCustomChannel(
      options.get<EndpointOption>(),
      options.get<GrpcCredentialOption>(),
      internal::MakeChannelArguments(options));
  auto service_grpc_stub =
      ::google::test::admin::database::v1::GoldenThingAdmin::NewStub(channel);
  auto longrunning_grpc_stub =
      google::longrunning::Operations::NewStub(channel);

  std::shared_ptr<GoldenThingAdminStub> stub =
      std::make_shared<DefaultGoldenThingAdminStub>(
          std::move(service_grpc_stub), std::move(longrunning_grpc_stub));

  stub = std::make_shared<GoldenThingAdminMetadata>(std::move(stub));

  if (internal::Contains(
      options.get<TracingComponentsOption>(), "rpc")) {
    GCP_LOG(INFO) << "Enabled logging for gRPC calls";
    stub = std::make_shared<GoldenThingAdminLogging>(
        std::move(stub),
        options.get<GrpcTracingOptionsOption>(),
        options.get<TracingComponentsOption>());
  }
  return stub;
}

}  // namespace GOOGLE_CLOUD_CPP_GENERATED_NS
}  // namespace golden_internal
}  // namespace cloud
}  // namespace google

