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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_SPANNER_INTERNAL_DATABASE_ADMIN_LOGGING_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_SPANNER_INTERNAL_DATABASE_ADMIN_LOGGING_H

#include "google/cloud/spanner/internal/database_admin_stub.h"
#include "google/cloud/spanner/tracing_options.h"
#include "google/cloud/spanner/version.h"
#include <memory>

namespace google {
namespace cloud {
namespace spanner {
inline namespace SPANNER_CLIENT_NS {
namespace internal {

/**
 * Implements the logging Decorator for DatabaseAdminStub.
 */
class DatabaseAdminLogging : public DatabaseAdminStub {
 public:
  DatabaseAdminLogging(std::shared_ptr<DatabaseAdminStub> child,
                       TracingOptions tracing_options)
      : child_(std::move(child)),
        tracing_options_(std::move(tracing_options)) {}

  ~DatabaseAdminLogging() override = default;

  //@{
  /**
   * @name Override the functions from `DatabaseAdminStub`.
   *
   * Run the logging loop (if appropriate) for the child DatabaseAdminStub.
   */
  ///
  StatusOr<google::longrunning::Operation> CreateDatabase(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::CreateDatabaseRequest const&
          request) override;

  StatusOr<google::spanner::admin::database::v1::Database> GetDatabase(
      grpc::ClientContext&,
      google::spanner::admin::database::v1::GetDatabaseRequest const&) override;

  StatusOr<google::spanner::admin::database::v1::GetDatabaseDdlResponse>
  GetDatabaseDdl(
      grpc::ClientContext&,
      google::spanner::admin::database::v1::GetDatabaseDdlRequest const&)
      override;

  StatusOr<google::longrunning::Operation> UpdateDatabase(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::UpdateDatabaseDdlRequest const&
          request) override;

  Status DropDatabase(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::DropDatabaseRequest const& request)
      override;

  StatusOr<google::spanner::admin::database::v1::ListDatabasesResponse>
  ListDatabases(
      grpc::ClientContext&,
      google::spanner::admin::database::v1::ListDatabasesRequest const&)
      override;

  StatusOr<google::longrunning::Operation> RestoreDatabase(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::RestoreDatabaseRequest const&
          request) override;

  StatusOr<google::iam::v1::Policy> GetIamPolicy(
      grpc::ClientContext& context,
      google::iam::v1::GetIamPolicyRequest const& request) override;

  StatusOr<google::iam::v1::Policy> SetIamPolicy(
      grpc::ClientContext& context,
      google::iam::v1::SetIamPolicyRequest const& request) override;

  StatusOr<google::iam::v1::TestIamPermissionsResponse> TestIamPermissions(
      grpc::ClientContext& context,
      google::iam::v1::TestIamPermissionsRequest const& request) override;

  StatusOr<google::longrunning::Operation> CreateBackup(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::CreateBackupRequest const& request)
      override;

  StatusOr<google::spanner::admin::database::v1::Backup> GetBackup(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::GetBackupRequest const& request)
      override;

  Status DeleteBackup(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::DeleteBackupRequest const& request)
      override;

  StatusOr<google::spanner::admin::database::v1::ListBackupsResponse>
  ListBackups(
      grpc::ClientContext&,
      google::spanner::admin::database::v1::ListBackupsRequest const&) override;

  StatusOr<google::spanner::admin::database::v1::Backup> UpdateBackup(
      grpc::ClientContext& context,
      google::spanner::admin::database::v1::UpdateBackupRequest const& request)
      override;

  StatusOr<google::spanner::admin::database::v1::ListBackupOperationsResponse>
  ListBackupOperations(
      grpc::ClientContext&,
      google::spanner::admin::database::v1::ListBackupOperationsRequest const&)
      override;

  StatusOr<google::spanner::admin::database::v1::ListDatabaseOperationsResponse>
  ListDatabaseOperations(grpc::ClientContext&,
                         google::spanner::admin::database::v1::
                             ListDatabaseOperationsRequest const&) override;

  StatusOr<google::longrunning::Operation> GetOperation(
      grpc::ClientContext& context,
      google::longrunning::GetOperationRequest const& request) override;

  std::unique_ptr<
      grpc::ClientAsyncResponseReaderInterface<google::longrunning::Operation>>
  AsyncGetOperation(grpc::ClientContext& context,
                    google::longrunning::GetOperationRequest const& request,
                    grpc::CompletionQueue* cq) override;

  Status CancelOperation(
      grpc::ClientContext& context,
      google::longrunning::CancelOperationRequest const& request) override;
  //@}

 private:
  std::shared_ptr<DatabaseAdminStub> child_;
  TracingOptions tracing_options_;
};

}  // namespace internal
}  // namespace SPANNER_CLIENT_NS
}  // namespace spanner
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_SPANNER_INTERNAL_DATABASE_ADMIN_LOGGING_H
