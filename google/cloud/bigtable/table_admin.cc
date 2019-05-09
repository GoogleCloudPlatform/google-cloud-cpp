// Copyright 2017 Google Inc.
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

#include "google/cloud/bigtable/table_admin.h"
#include "google/cloud/bigtable/internal/async_retry_multi_page.h"
#include "google/cloud/bigtable/internal/async_retry_unary_rpc.h"
#include "google/cloud/bigtable/internal/grpc_error_delegate.h"
#include "google/cloud/bigtable/internal/poll_longrunning_operation.h"
#include "google/cloud/bigtable/internal/unary_client_utils.h"
#include <google/protobuf/duration.pb.h>
#include <sstream>

namespace btadmin = ::google::bigtable::admin::v2;

namespace google {
namespace cloud {
namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
static_assert(std::is_copy_constructible<bigtable::TableAdmin>::value,
              "bigtable::TableAdmin must be constructible");
static_assert(std::is_copy_assignable<bigtable::TableAdmin>::value,
              "bigtable::TableAdmin must be assignable");

constexpr TableAdmin::TableView TableAdmin::VIEW_UNSPECIFIED;
constexpr TableAdmin::TableView TableAdmin::NAME_ONLY;
constexpr TableAdmin::TableView TableAdmin::SCHEMA_VIEW;
constexpr TableAdmin::TableView TableAdmin::REPLICATION_VIEW;
constexpr TableAdmin::TableView TableAdmin::FULL;

/// Shortcuts to avoid typing long names over and over.
using ClientUtils = bigtable::internal::noex::UnaryClientUtils<AdminClient>;

StatusOr<btadmin::Table> TableAdmin::CreateTable(std::string table_id,
                                                 TableConfig config) {
  grpc::Status status;

  auto request = std::move(config).as_proto();
  request.set_parent(instance_name());
  request.set_table_id(std::move(table_id));

  // This is a non-idempotent API, use the correct retry loop for this type of
  // operation.
  auto result = ClientUtils::MakeNonIdemponentCall(
      *client_, clone_rpc_retry_policy(), clone_metadata_update_policy(),
      &AdminClient::CreateTable, request, "CreateTable", status);

  if (!status.ok()) {
    return internal::MakeStatusFromRpcError(status);
  }
  return result;
}

future<StatusOr<btadmin::Table>> TableAdmin::AsyncCreateTable(
    CompletionQueue& cq, std::string table_id, TableConfig config) {
  btadmin::CreateTableRequest request = std::move(config).as_proto();
  request.set_parent(instance_name());
  request.set_table_id(std::move(table_id));

  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
      __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
      internal::ConstantIdempotencyPolicy(false),
      clone_metadata_update_policy(),
      [client](grpc::ClientContext* context,
               btadmin::CreateTableRequest const& request,
               grpc::CompletionQueue* cq) {
        return client->AsyncCreateTable(context, request, cq);
      },
      std::move(request), cq);
}

future<StatusOr<google::bigtable::admin::v2::Table>> TableAdmin::AsyncGetTable(
    CompletionQueue& cq, std::string const& table_id,
    btadmin::Table::View view) {
  google::bigtable::admin::v2::GetTableRequest request{};
  request.set_name(TableName(table_id));
  request.set_view(view);

  // Copy the client because we lack C++14 extended lambda captures.
  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
      __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
      internal::ConstantIdempotencyPolicy(true), clone_metadata_update_policy(),
      [client](grpc::ClientContext* context,
               google::bigtable::admin::v2::GetTableRequest const& request,
               grpc::CompletionQueue* cq) {
        return client->AsyncGetTable(context, request, cq);
      },
      std::move(request), cq);
}

StatusOr<std::vector<btadmin::Table>> TableAdmin::ListTables(
    btadmin::Table::View view) {
  grpc::Status status;

  // Copy the policies in effect for the operation.
  auto rpc_policy = clone_rpc_retry_policy();
  auto backoff_policy = clone_rpc_backoff_policy();

  // Build the RPC request, try to minimize copying.
  std::vector<btadmin::Table> result;
  std::string page_token;
  do {
    btadmin::ListTablesRequest request;
    request.set_page_token(std::move(page_token));
    request.set_parent(instance_name());
    request.set_view(view);

    auto response = ClientUtils::MakeCall(
        *client_, *rpc_policy, *backoff_policy, clone_metadata_update_policy(),
        &AdminClient::ListTables, request, "TableAdmin", status, true);

    if (!status.ok()) {
      return internal::MakeStatusFromRpcError(status);
    }

    for (auto& x : *response.mutable_tables()) {
      result.emplace_back(std::move(x));
    }
    page_token = std::move(*response.mutable_next_page_token());
  } while (!page_token.empty());
  return result;
}

future<StatusOr<std::vector<btadmin::Table>>> TableAdmin::AsyncListTables(
    CompletionQueue& cq, btadmin::Table::View view) {
  auto client = client_;
  btadmin::ListTablesRequest request;
  request.set_parent(instance_name());
  request.set_view(view);

  return internal::StartAsyncRetryMultiPage(
      __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
      clone_metadata_update_policy(),
      [client](grpc::ClientContext* context,
               btadmin::ListTablesRequest const& request,
               grpc::CompletionQueue* cq) {
        return client->AsyncListTables(context, request, cq);
      },
      std::move(request), std::vector<btadmin::Table>(),
      [](std::vector<btadmin::Table> acc,
         btadmin::ListTablesResponse response) {
        std::move(response.tables().begin(), response.tables().end(),
                  std::back_inserter(acc));
        return acc;
      },
      cq);
}

StatusOr<btadmin::Table> TableAdmin::GetTable(std::string const& table_id,
                                              btadmin::Table::View view) {
  grpc::Status status;
  btadmin::GetTableRequest request;
  request.set_name(TableName(table_id));
  request.set_view(view);

  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);

  auto result = ClientUtils::MakeCall(
      *client_, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
      metadata_update_policy, &AdminClient::GetTable, request, "GetTable",
      status, true);
  if (!status.ok()) {
    return internal::MakeStatusFromRpcError(status);
  }

  return result;
}

Status TableAdmin::DeleteTable(std::string const& table_id) {
  grpc::Status status;
  btadmin::DeleteTableRequest request;
  request.set_name(TableName(table_id));

  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);

  // This is a non-idempotent API, use the correct retry loop for this type of
  // operation.
  ClientUtils::MakeNonIdemponentCall(
      *client_, clone_rpc_retry_policy(), metadata_update_policy,
      &AdminClient::DeleteTable, request, "DeleteTable", status);

  return internal::MakeStatusFromRpcError(status);
}

future<Status> TableAdmin::AsyncDeleteTable(CompletionQueue& cq,
                                            std::string const& table_id) {
  grpc::Status status;
  btadmin::DeleteTableRequest request;
  request.set_name(TableName(table_id));

  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);

  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
             __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
             internal::ConstantIdempotencyPolicy(true),
             clone_metadata_update_policy(),
             [client](
                 grpc::ClientContext* context,
                 google::bigtable::admin::v2::DeleteTableRequest const& request,
                 grpc::CompletionQueue* cq) {
               return client->AsyncDeleteTable(context, request, cq);
             },
             std::move(request), cq)
      .then([](future<StatusOr<google::protobuf::Empty>> r) {
        return r.get().status();
      });
}

StatusOr<btadmin::Table> TableAdmin::ModifyColumnFamilies(
    std::string const& table_id,
    std::vector<ColumnFamilyModification> modifications) {
  grpc::Status status;

  btadmin::ModifyColumnFamiliesRequest request;
  request.set_name(TableName(table_id));
  for (auto& m : modifications) {
    *request.add_modifications() = std::move(m).as_proto();
  }
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);
  auto result = ClientUtils::MakeNonIdemponentCall(
      *client_, clone_rpc_retry_policy(), metadata_update_policy,
      &AdminClient::ModifyColumnFamilies, request, "ModifyColumnFamilies",
      status);

  if (!status.ok()) {
    return internal::MakeStatusFromRpcError(status);
  }
  return result;
}

future<StatusOr<btadmin::Table>> TableAdmin::AsyncModifyColumnFamilies(
    CompletionQueue& cq, std::string const& table_id,
    std::vector<ColumnFamilyModification> modifications) {
  btadmin::ModifyColumnFamiliesRequest request;
  request.set_name(TableName(table_id));
  for (auto& m : modifications) {
    *request.add_modifications() = std::move(m).as_proto();
  }
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);

  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
      __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
      internal::ConstantIdempotencyPolicy(true), metadata_update_policy,
      [client](grpc::ClientContext* context,
               btadmin::ModifyColumnFamiliesRequest const& request,
               grpc::CompletionQueue* cq) {
        return client->AsyncModifyColumnFamilies(context, request, cq);
      },
      std::move(request), cq);
}

Status TableAdmin::DropRowsByPrefix(std::string const& table_id,
                                    std::string row_key_prefix) {
  grpc::Status status;
  btadmin::DropRowRangeRequest request;
  request.set_name(TableName(table_id));
  request.set_row_key_prefix(std::move(row_key_prefix));
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);
  ClientUtils::MakeNonIdemponentCall(
      *client_, clone_rpc_retry_policy(), metadata_update_policy,
      &AdminClient::DropRowRange, request, "DropRowByPrefix", status);

  return internal::MakeStatusFromRpcError(status);
}

future<Status> TableAdmin::AsyncDropRowsByPrefix(CompletionQueue& cq,
                                                 std::string const& table_id,
                                                 std::string row_key_prefix) {
  google::bigtable::admin::v2::DropRowRangeRequest request;
  request.set_name(TableName(table_id));
  request.set_row_key_prefix(std::move(row_key_prefix));
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);
  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
             __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
             internal::ConstantIdempotencyPolicy(true), metadata_update_policy,
             [client](grpc::ClientContext* context,
                      btadmin::DropRowRangeRequest const& request,
                      grpc::CompletionQueue* cq) {
               return client->AsyncDropRowRange(context, request, cq);
             },
             std::move(request), cq)
      .then([](future<StatusOr<google::protobuf::Empty>> r) {
        return r.get().status();
      });
}

Status TableAdmin::DropAllRows(std::string const& table_id) {
  grpc::Status status;
  btadmin::DropRowRangeRequest request;
  request.set_name(TableName(table_id));
  request.set_delete_all_data_from_table(true);
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);
  ClientUtils::MakeNonIdemponentCall(
      *client_, clone_rpc_retry_policy(), metadata_update_policy,
      &AdminClient::DropRowRange, request, "DropAllRows", status);

  return internal::MakeStatusFromRpcError(status);
}

future<Status> TableAdmin::AsyncDropAllRows(CompletionQueue& cq,
                                            std::string const& table_id) {
  google::bigtable::admin::v2::DropRowRangeRequest request;
  request.set_name(TableName(table_id));
  request.set_delete_all_data_from_table(true);
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);
  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
             __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
             internal::ConstantIdempotencyPolicy(true), metadata_update_policy,
             [client](grpc::ClientContext* context,
                      btadmin::DropRowRangeRequest const& request,
                      grpc::CompletionQueue* cq) {
               return client->AsyncDropRowRange(context, request, cq);
             },
             std::move(request), cq)
      .then([](future<StatusOr<google::protobuf::Empty>> r) {
        return r.get().status();
      });
}

StatusOr<ConsistencyToken> TableAdmin::GenerateConsistencyToken(
    std::string const& table_id) {
  grpc::Status status;
  btadmin::GenerateConsistencyTokenRequest request;
  request.set_name(TableName(table_id));
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);

  auto response = ClientUtils::MakeCall(
      *client_, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
      metadata_update_policy, &AdminClient::GenerateConsistencyToken, request,
      "GenerateConsistencyToken", status, true);

  if (!status.ok()) {
    return internal::MakeStatusFromRpcError(status);
  }
  return ConsistencyToken(*response.mutable_consistency_token());
}

future<StatusOr<ConsistencyToken>> TableAdmin::AsyncGenerateConsistencyToken(
    CompletionQueue& cq, std::string const& table_id) {
  btadmin::GenerateConsistencyTokenRequest request;
  request.set_name(TableName(table_id));
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id);
  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
             __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
             internal::ConstantIdempotencyPolicy(true), metadata_update_policy,
             [client](grpc::ClientContext* context,
                      btadmin::GenerateConsistencyTokenRequest const& request,
                      grpc::CompletionQueue* cq) {
               return client->AsyncGenerateConsistencyToken(context, request,
                                                            cq);
             },
             std::move(request), cq)
      .then([](future<StatusOr<btadmin::GenerateConsistencyTokenResponse>> fut)
                -> StatusOr<ConsistencyToken> {
        auto result = fut.get();
        if (!result) {
          return result.status();
        }
        return ConsistencyToken(*result->mutable_consistency_token());
      });
}

StatusOr<Consistency> TableAdmin::CheckConsistency(
    bigtable::TableId const& table_id,
    bigtable::ConsistencyToken const& consistency_token) {
  grpc::Status status;
  btadmin::CheckConsistencyRequest request;
  request.set_name(TableName(table_id.get()));
  request.set_consistency_token(consistency_token.get());
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id.get());

  auto response = ClientUtils::MakeCall(
      *client_, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
      metadata_update_policy, &AdminClient::CheckConsistency, request,
      "CheckConsistency", status, true);

  if (!status.ok()) {
    return internal::MakeStatusFromRpcError(status);
  }

  return response.consistent() ? Consistency::kConsistent
                               : Consistency::kInconsistent;
}

future<StatusOr<Consistency>> TableAdmin::AsyncCheckConsistency(
    CompletionQueue& cq, bigtable::TableId const& table_id,
    bigtable::ConsistencyToken const& consistency_token) {
  btadmin::CheckConsistencyRequest request;
  request.set_name(TableName(table_id.get()));
  request.set_consistency_token(consistency_token.get());
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id.get());
  auto client = client_;
  return internal::StartRetryAsyncUnaryRpc(
             __func__, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
             internal::ConstantIdempotencyPolicy(true), metadata_update_policy,
             [client](grpc::ClientContext* context,
                      btadmin::CheckConsistencyRequest const& request,
                      grpc::CompletionQueue* cq) {
               return client->AsyncCheckConsistency(context, request, cq);
             },
             std::move(request), cq)
      .then([](future<StatusOr<btadmin::CheckConsistencyResponse>> fut)
                -> StatusOr<Consistency> {
        auto result = fut.get();
        if (!result) {
          return result.status();
        }

        return result->consistent() ? Consistency::kConsistent
                                    : Consistency::kInconsistent;
        ;
      });
}
StatusOr<Consistency> TableAdmin::WaitForConsistencyCheckImpl(
    bigtable::TableId const& table_id,
    bigtable::ConsistencyToken const& consistency_token) {
  grpc::Status status;
  btadmin::CheckConsistencyRequest request;
  request.set_name(TableName(table_id.get()));
  request.set_consistency_token(consistency_token.get());
  MetadataUpdatePolicy metadata_update_policy(
      instance_name(), MetadataParamTypes::NAME, table_id.get());

  // TODO(#1918) - make use of polling policy deadlines
  auto polling_policy = clone_polling_policy();
  do {
    auto response = ClientUtils::MakeCall(
        *client_, clone_rpc_retry_policy(), clone_rpc_backoff_policy(),
        metadata_update_policy, &AdminClient::CheckConsistency, request,
        "CheckConsistency", status, true);

    if (status.ok()) {
      if (response.consistent()) {
        return Consistency::kConsistent;
      }
    } else if (polling_policy->IsPermanentError(status)) {
      return bigtable::internal::MakeStatusFromRpcError(status);
    }
  } while (!polling_policy->Exhausted());

  return bigtable::internal::MakeStatusFromRpcError(status);
}

std::string TableAdmin::InstanceName() const {
  return "projects/" + client_->project() + "/instances/" + instance_id_;
}

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google
