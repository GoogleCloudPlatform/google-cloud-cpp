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
// source: google/iam/admin/v1/iam.proto
#include "google/cloud/iam/iam_connection_idempotency_policy.h"
#include "absl/memory/memory.h"
#include <memory>

namespace google {
namespace cloud {
namespace iam {
inline namespace GOOGLE_CLOUD_CPP_GENERATED_NS {

using google::cloud::internal::Idempotency;

IAMConnectionIdempotencyPolicy::~IAMConnectionIdempotencyPolicy() = default;

namespace {
class DefaultIAMConnectionIdempotencyPolicy
    : public IAMConnectionIdempotencyPolicy {
 public:
  ~DefaultIAMConnectionIdempotencyPolicy() override = default;

  /// Create a new copy of this object.
  std::unique_ptr<IAMConnectionIdempotencyPolicy> clone() const override {
    return absl::make_unique<DefaultIAMConnectionIdempotencyPolicy>(*this);
  }

  Idempotency ListServiceAccounts(
      google::iam::admin::v1::ListServiceAccountsRequest) override {
    return Idempotency::kIdempotent;
  }

  Idempotency GetServiceAccount(
      google::iam::admin::v1::GetServiceAccountRequest const&) override {
    return Idempotency::kIdempotent;
  }

  Idempotency CreateServiceAccount(
      google::iam::admin::v1::CreateServiceAccountRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency PatchServiceAccount(
      google::iam::admin::v1::PatchServiceAccountRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency DeleteServiceAccount(
      google::iam::admin::v1::DeleteServiceAccountRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency UndeleteServiceAccount(
      google::iam::admin::v1::UndeleteServiceAccountRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency EnableServiceAccount(
      google::iam::admin::v1::EnableServiceAccountRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency DisableServiceAccount(
      google::iam::admin::v1::DisableServiceAccountRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency ListServiceAccountKeys(
      google::iam::admin::v1::ListServiceAccountKeysRequest const&) override {
    return Idempotency::kIdempotent;
  }

  Idempotency GetServiceAccountKey(
      google::iam::admin::v1::GetServiceAccountKeyRequest const&) override {
    return Idempotency::kIdempotent;
  }

  Idempotency CreateServiceAccountKey(
      google::iam::admin::v1::CreateServiceAccountKeyRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency UploadServiceAccountKey(
      google::iam::admin::v1::UploadServiceAccountKeyRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency DeleteServiceAccountKey(
      google::iam::admin::v1::DeleteServiceAccountKeyRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency GetIamPolicy(
      google::iam::v1::GetIamPolicyRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency SetIamPolicy(
      google::iam::v1::SetIamPolicyRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency TestIamPermissions(
      google::iam::v1::TestIamPermissionsRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency QueryGrantableRoles(
      google::iam::admin::v1::QueryGrantableRolesRequest) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency ListRoles(google::iam::admin::v1::ListRolesRequest) override {
    return Idempotency::kIdempotent;
  }

  Idempotency GetRole(google::iam::admin::v1::GetRoleRequest const&) override {
    return Idempotency::kIdempotent;
  }

  Idempotency CreateRole(
      google::iam::admin::v1::CreateRoleRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency UpdateRole(
      google::iam::admin::v1::UpdateRoleRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency DeleteRole(
      google::iam::admin::v1::DeleteRoleRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency UndeleteRole(
      google::iam::admin::v1::UndeleteRoleRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency QueryTestablePermissions(
      google::iam::admin::v1::QueryTestablePermissionsRequest) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency QueryAuditableServices(
      google::iam::admin::v1::QueryAuditableServicesRequest const&) override {
    return Idempotency::kNonIdempotent;
  }

  Idempotency LintPolicy(
      google::iam::admin::v1::LintPolicyRequest const&) override {
    return Idempotency::kNonIdempotent;
  }
};
}  // namespace

std::unique_ptr<IAMConnectionIdempotencyPolicy>
MakeDefaultIAMConnectionIdempotencyPolicy() {
  return absl::make_unique<DefaultIAMConnectionIdempotencyPolicy>();
}

}  // namespace GOOGLE_CLOUD_CPP_GENERATED_NS
}  // namespace iam
}  // namespace cloud
}  // namespace google
