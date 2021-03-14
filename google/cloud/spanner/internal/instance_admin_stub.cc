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

#include "google/cloud/spanner/internal/instance_admin_stub.h"
#include "google/cloud/spanner/internal/instance_admin_logging.h"
#include "google/cloud/spanner/internal/instance_admin_metadata.h"
#include "google/cloud/grpc_error_delegate.h"
#include "google/cloud/internal/algorithm.h"
#include "google/cloud/internal/common_options.h"
#include "google/cloud/internal/grpc_options.h"
#include "google/cloud/log.h"
#include <google/longrunning/operations.grpc.pb.h>
#include <google/spanner/admin/instance/v1/spanner_instance_admin.grpc.pb.h>
#include <grpcpp/grpcpp.h>

namespace google {
namespace cloud {
namespace spanner_internal {
inline namespace SPANNER_CLIENT_NS {

namespace gcsa = ::google::spanner::admin::instance::v1;
namespace giam = ::google::iam::v1;

InstanceAdminStub::~InstanceAdminStub() = default;

class DefaultInstanceAdminStub : public InstanceAdminStub {
 public:
  DefaultInstanceAdminStub(
      std::unique_ptr<gcsa::InstanceAdmin::Stub> instance_admin,
      std::unique_ptr<google::longrunning::Operations::Stub> operations)
      : instance_admin_(std::move(instance_admin)),
        operations_(std::move(operations)) {}

  ~DefaultInstanceAdminStub() override = default;

  StatusOr<gcsa::Instance> GetInstance(
      grpc::ClientContext& context,
      gcsa::GetInstanceRequest const& request) override {
    gcsa::Instance response;
    auto status = instance_admin_->GetInstance(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<google::longrunning::Operation> CreateInstance(
      grpc::ClientContext& context,
      gcsa::CreateInstanceRequest const& request) override {
    google::longrunning::Operation response;
    grpc::Status status =
        instance_admin_->CreateInstance(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<google::longrunning::Operation> UpdateInstance(
      grpc::ClientContext& context,
      gcsa::UpdateInstanceRequest const& request) override {
    google::longrunning::Operation response;
    grpc::Status status =
        instance_admin_->UpdateInstance(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  Status DeleteInstance(grpc::ClientContext& context,
                        gcsa::DeleteInstanceRequest const& request) override {
    google::protobuf::Empty response;
    grpc::Status status =
        instance_admin_->DeleteInstance(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return google::cloud::Status();
  }

  StatusOr<gcsa::InstanceConfig> GetInstanceConfig(
      grpc::ClientContext& context,
      gcsa::GetInstanceConfigRequest const& request) override {
    gcsa::InstanceConfig response;
    auto status =
        instance_admin_->GetInstanceConfig(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<gcsa::ListInstanceConfigsResponse> ListInstanceConfigs(
      grpc::ClientContext& context,
      gcsa::ListInstanceConfigsRequest const& request) override {
    gcsa::ListInstanceConfigsResponse response;
    auto status =
        instance_admin_->ListInstanceConfigs(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<gcsa::ListInstancesResponse> ListInstances(
      grpc::ClientContext& context,
      gcsa::ListInstancesRequest const& request) override {
    gcsa::ListInstancesResponse response;
    auto status = instance_admin_->ListInstances(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<giam::Policy> GetIamPolicy(
      grpc::ClientContext& context,
      giam::GetIamPolicyRequest const& request) override {
    giam::Policy response;
    auto status = instance_admin_->GetIamPolicy(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<giam::Policy> SetIamPolicy(
      grpc::ClientContext& context,
      giam::SetIamPolicyRequest const& request) override {
    giam::Policy response;
    auto status = instance_admin_->SetIamPolicy(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<giam::TestIamPermissionsResponse> TestIamPermissions(
      grpc::ClientContext& context,
      giam::TestIamPermissionsRequest const& request) override {
    giam::TestIamPermissionsResponse response;
    auto status =
        instance_admin_->TestIamPermissions(&context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

  StatusOr<google::longrunning::Operation> GetOperation(
      grpc::ClientContext& client_context,
      google::longrunning::GetOperationRequest const& request) override {
    google::longrunning::Operation response;
    grpc::Status status =
        operations_->GetOperation(&client_context, request, &response);
    if (!status.ok()) {
      return google::cloud::MakeStatusFromRpcError(status);
    }
    return response;
  }

 private:
  std::unique_ptr<gcsa::InstanceAdmin::Stub> instance_admin_;
  std::unique_ptr<google::longrunning::Operations::Stub> operations_;
};

std::shared_ptr<InstanceAdminStub> CreateDefaultInstanceAdminStub(
    Options const& opts) {
  auto channel_args = internal::MakeChannelArguments(opts);
  auto channel = grpc::CreateCustomChannel(
      opts.get<internal::EndpointOption>(),
      opts.get<internal::GrpcCredentialOption>(), channel_args);
  auto spanner_grpc_stub = gcsa::InstanceAdmin::NewStub(channel);
  auto longrunning_grpc_stub =
      google::longrunning::Operations::NewStub(channel);

  std::shared_ptr<InstanceAdminStub> stub =
      std::make_shared<DefaultInstanceAdminStub>(
          std::move(spanner_grpc_stub), std::move(longrunning_grpc_stub));

  stub = std::make_shared<InstanceAdminMetadata>(std::move(stub));

  if (internal::Contains(opts.get<internal::TracingComponentsOption>(),
                         "rpc")) {
    GCP_LOG(INFO) << "Enabled logging for gRPC calls";
    stub = std::make_shared<InstanceAdminLogging>(
        std::move(stub), opts.get<internal::GrpcTracingOptionsOption>());
  }
  return stub;
}

}  // namespace SPANNER_CLIENT_NS
}  // namespace spanner_internal
}  // namespace cloud
}  // namespace google
