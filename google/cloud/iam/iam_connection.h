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
#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_IAM_IAM_CONNECTION_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_IAM_IAM_CONNECTION_H

#include "google/cloud/iam/iam_connection_idempotency_policy.h"
#include "google/cloud/iam/internal/iam_stub.h"
#include "google/cloud/iam/retry_traits.h"
#include "google/cloud/backoff_policy.h"
#include "google/cloud/options.h"
#include "google/cloud/status_or.h"
#include "google/cloud/stream_range.h"
#include "google/cloud/version.h"
#include <memory>

namespace google {
namespace cloud {
namespace iam {
inline namespace GOOGLE_CLOUD_CPP_GENERATED_NS {

using IAMRetryPolicy = google::cloud::internal::TraitBasedRetryPolicy<
    iam_internal::IAMRetryTraits>;

using IAMLimitedTimeRetryPolicy =
    google::cloud::internal::LimitedTimeRetryPolicy<
        iam_internal::IAMRetryTraits>;

using IAMLimitedErrorCountRetryPolicy =
    google::cloud::internal::LimitedErrorCountRetryPolicy<
        iam_internal::IAMRetryTraits>;

class IAMConnection {
 public:
  virtual ~IAMConnection() = 0;

  virtual StreamRange<::google::iam::admin::v1::ServiceAccount>
  ListServiceAccounts(
      ::google::iam::admin::v1::ListServiceAccountsRequest request);

  virtual StatusOr<::google::iam::admin::v1::ServiceAccount> GetServiceAccount(
      ::google::iam::admin::v1::GetServiceAccountRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::ServiceAccount>
  CreateServiceAccount(
      ::google::iam::admin::v1::CreateServiceAccountRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::ServiceAccount>
  PatchServiceAccount(
      ::google::iam::admin::v1::PatchServiceAccountRequest const& request);

  virtual Status DeleteServiceAccount(
      ::google::iam::admin::v1::DeleteServiceAccountRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::UndeleteServiceAccountResponse>
  UndeleteServiceAccount(
      ::google::iam::admin::v1::UndeleteServiceAccountRequest const& request);

  virtual Status EnableServiceAccount(
      ::google::iam::admin::v1::EnableServiceAccountRequest const& request);

  virtual Status DisableServiceAccount(
      ::google::iam::admin::v1::DisableServiceAccountRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::ListServiceAccountKeysResponse>
  ListServiceAccountKeys(
      ::google::iam::admin::v1::ListServiceAccountKeysRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::ServiceAccountKey>
  GetServiceAccountKey(
      ::google::iam::admin::v1::GetServiceAccountKeyRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::ServiceAccountKey>
  CreateServiceAccountKey(
      ::google::iam::admin::v1::CreateServiceAccountKeyRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::ServiceAccountKey>
  UploadServiceAccountKey(
      ::google::iam::admin::v1::UploadServiceAccountKeyRequest const& request);

  virtual Status DeleteServiceAccountKey(
      ::google::iam::admin::v1::DeleteServiceAccountKeyRequest const& request);

  virtual StatusOr<::google::iam::v1::Policy> GetIamPolicy(
      ::google::iam::v1::GetIamPolicyRequest const& request);

  virtual StatusOr<::google::iam::v1::Policy> SetIamPolicy(
      ::google::iam::v1::SetIamPolicyRequest const& request);

  virtual StatusOr<::google::iam::v1::TestIamPermissionsResponse>
  TestIamPermissions(
      ::google::iam::v1::TestIamPermissionsRequest const& request);

  virtual StreamRange<::google::iam::admin::v1::Role> QueryGrantableRoles(
      ::google::iam::admin::v1::QueryGrantableRolesRequest request);

  virtual StreamRange<::google::iam::admin::v1::Role> ListRoles(
      ::google::iam::admin::v1::ListRolesRequest request);

  virtual StatusOr<::google::iam::admin::v1::Role> GetRole(
      ::google::iam::admin::v1::GetRoleRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::Role> CreateRole(
      ::google::iam::admin::v1::CreateRoleRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::Role> UpdateRole(
      ::google::iam::admin::v1::UpdateRoleRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::Role> DeleteRole(
      ::google::iam::admin::v1::DeleteRoleRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::Role> UndeleteRole(
      ::google::iam::admin::v1::UndeleteRoleRequest const& request);

  virtual StreamRange<::google::iam::admin::v1::Permission>
  QueryTestablePermissions(
      ::google::iam::admin::v1::QueryTestablePermissionsRequest request);

  virtual StatusOr<::google::iam::admin::v1::QueryAuditableServicesResponse>
  QueryAuditableServices(
      ::google::iam::admin::v1::QueryAuditableServicesRequest const& request);

  virtual StatusOr<::google::iam::admin::v1::LintPolicyResponse> LintPolicy(
      ::google::iam::admin::v1::LintPolicyRequest const& request);
};

std::shared_ptr<IAMConnection> MakeIAMConnection(Options options = {});

std::shared_ptr<IAMConnection> MakeIAMConnection(
    std::shared_ptr<iam_internal::IAMStub> stub, Options options = {});

}  // namespace GOOGLE_CLOUD_CPP_GENERATED_NS
}  // namespace iam
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_IAM_IAM_CONNECTION_H
