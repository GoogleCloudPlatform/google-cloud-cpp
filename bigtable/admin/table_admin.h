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

#ifndef GOOGLE_CLOUD_CPP_BIGTABLE_ADMIN_TABLE_ADMIN_H_
#define GOOGLE_CLOUD_CPP_BIGTABLE_ADMIN_TABLE_ADMIN_H_

#include "bigtable/admin/admin_client.h"

#include <memory>

#include "bigtable/client/rpc_backoff_policy.h"
#include "bigtable/client/rpc_retry_policy.h"

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Implements the API to administer tables instance a Cloud Bigtable instance.
 */
class TableAdmin {
 public:
  /**
   * @param client the interface to create grpc stubs, report errors, etc.
   * @param instance_id the id of the instance, e.g., "my-instance", the full
   *   name (e.g. '/projects/my-project/instances/my-instance') is built using
   *   the project id in the @p client parameter.
   */
  TableAdmin(std::shared_ptr<AdminClient> client, std::string instance_id)
      : client_(client),
        instance_id_(std::move(instance_id)),
        instance_name_(CreateInstanceName()),
        rpc_retry_policy_(DefaultRPCRetryPolicy()),
        rpc_backoff_policy_(DefaultRPCBackoffPolicy()) {}

  /**
   * Create a new TableAdmin using explicit policies to handle RPC errors.
   *
   * @tparam RPCRetryPolicy control which operations to retry and for how long.
   * @tparam RPCBackoffPolicy control how does the client backs off after an RPC
   *     error.
   * @param client the interface to create grpc stubs, report errors, etc.
   * @param instance_id the id of the instance, e.g., "my-instance", the full
   *   name (e.g. '/projects/my-project/instances/my-instance') is built using
   *   the project id in the @p client parameter.
   * @param retry_policy the policy to handle RPC errors.
   * @param backoff_policy the policy to control backoff after an error.
   */
  template <typename RPCRetryPolicy, typename RPCBackoffPolicy>
  TableAdmin(std::shared_ptr<AdminClient> client, std::string instance_id,
             RPCRetryPolicy retry_policy, RPCBackoffPolicy backoff_policy)
      : client_(client),
        instance_id_(std::move(instance_id)),
        instance_name_(CreateInstanceName()),
        rpc_retry_policy_(retry_policy.clone()),
        rpc_backoff_policy_(backoff_policy.clone()) {}

  std::string const& instance_id() const { return instance_id_; }
  std::string const& instance_name() const { return instance_name_; }

  /**
   * Return all the tables in the instance.
   *
   * @param view define what information about the tables is retrieved.
   *   - VIEW_UNSPECIFIED: equivalent to VIEW_SCHEMA.
   *   - NAME: return only the name of the table.
   *   - VIEW_SCHEMA: return the name and the schema.
   *   - FULL: return all the information about the table.
   */
  std::vector<::google::bigtable::admin::v2::Table> ListTables(
      ::google::bigtable::admin::v2::Table::View view);

 private:
  std::string CreateInstanceName() const;

 private:
  std::shared_ptr<AdminClient> client_;
  std::string instance_id_;
  std::string instance_name_;
  std::unique_ptr<RPCRetryPolicy> rpc_retry_policy_;
  std::unique_ptr<RPCBackoffPolicy> rpc_backoff_policy_;
};

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // GOOGLE_CLOUD_CPP_BIGTABLE_ADMIN_TABLE_ADMIN_H_
