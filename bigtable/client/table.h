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

#ifndef GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_TABLE_H_
#define GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_TABLE_H_

#include "bigtable/client/data_client.h"
#include "bigtable/client/filters.h"
#include "bigtable/client/idempotent_mutation_policy.h"
#include "bigtable/client/internal/unary_rpc_utils.h"
#include "bigtable/client/metadata_update_policy.h"
#include "bigtable/client/mutations.h"
#include "bigtable/client/read_modify_write_rule.h"
#include "bigtable/client/row_reader.h"
#include "bigtable/client/row_set.h"
#include "bigtable/client/rpc_backoff_policy.h"
#include "bigtable/client/rpc_retry_policy.h"
#include <google/bigtable/v2/bigtable.grpc.pb.h>

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Return the full table name.
 *
 * The full table name is:
 *
 * `projects/<PROJECT_ID>/instances/<INSTANCE_ID>/tables/<table_id>`
 *
 * Where the project id and instance id come from the @p client parameter.
 */
inline std::string TableName(std::shared_ptr<DataClient> client,
                             std::string const& table_id) {
  return InstanceName(std::move(client)) + "/tables/" + table_id;
}

/**
 * The main interface to interact with data in a Cloud Bigtable table.
 *
 * This class provides member functions to:
 * - read specific rows: `Table::ReadRow()`
 * - scan a ranges of rows: `Table::ReadRows()`
 * - update or create a single row: `Table::Apply()`
 * - update or modify multiple rows: `Table::BulkApply()`
 * - update a row based on previous values: `Table::CheckAndMutateRow()`
 *
 * The class deals with the most common transient failures, and retries the
 * underlying RPC calls subject to the policies configured by the application.
 * These policies are documented in`Table::Table()`.
 */
class Table {
 public:
  /// A simple wrapper to represent the response from `Table::SampleRowKeys()`.
  struct RowKeySample {
    std::string row_key;
    std::int64_t offset_bytes;
  };

  /**
   * Constructor with default policies.
   *
   * @param client how to communicate with Cloud Bigtable, including
   *     credentials, the project id, and the instance id.
   * @param table_id the table id within the instance defined by client.  The
   *     full table name is `client->instance_name() + '/tables/' + table_id`.
   */
  Table(std::shared_ptr<DataClient> client, std::string const& table_id)
      : client_(std::move(client)),
        table_name_(TableName(client_, table_id)),
        rpc_retry_policy_(bigtable::DefaultRPCRetryPolicy()),
        rpc_backoff_policy_(bigtable::DefaultRPCBackoffPolicy()),
        metadata_update_policy_(table_name(), MetadataParamTypes::TABLE_NAME),
        idempotent_mutation_policy_(
            bigtable::DefaultIdempotentMutationPolicy()) {}

  /**
   * Constructor with explicit policies.
   *
   * The policies are passed by value, because this makes it easy for
   * applications to create them.  For example:
   *
   * @code
   * using namespace std::chrono_literals; // assuming C++14.
   * auto client = bigtable::CreateDefaultClient(...); // details ommitted
   * bigtable::Table table(client, "my-table",
   *                       // Allow up to 20 minutes to retry operations
   *                       bigtable::LimitedTimeRetryPolicy(20min),
   *                       // Start with 50 milliseconds backoff, grow
   *                       // exponentially to 5 minutes.
   *                       bigtable::ExponentialBackoffPolicy(50ms, 5min),
   *                       // Only retry idempotent mutations.
   *                       bigtable::SafeIdempotentMutationPolicy());
   * @endcode
   *
   * @param client how to communicate with Cloud Bigtable, including
   *     credentials, the project id, and the instance id.
   * @param table_id the table id within the instance defined by client.  The
   *     full table name is `client->instance_name() + "/tables/" + table_id`.
   * @param retry_policy the value of the `RPCRetryPolicy`, for example, the
   *     policy type may be `LimitedErrorCountRetryPolicy` which
   *     tolerates a maximum number of errors, the value controls how many.
   * @param backoff_policy the value of the `RPCBackoffPolicy`, for example, the
   *     policy type may be `ExponentialBackoffPolicy` which will
   *     double the wait period on each failure, up to a limit.  The value
   *     controls the initial and maximum wait periods.
   * @param idempotent_mutation_policy the value of the
   *     `IdempotentMutationPolicy`. The policies implemented by this library
   *     (`SafeIdempotentMutationPolicy` and `AlwaysRetryMutationPolicy`) are
   *     stateless, but the application may implement stateful policies.
   *
   * @tparam IdempotentMutationPolicy which mutations are retried. Use
   *     `SafeIdempotentMutationPolicy` to only retry idempotent operations, use
   *     `AlwaysRetryMutationPolicy` to retry all operations.  Read the caveats
   *     in the class defintion to understand the downsides of the latter. You
   *     can also create your own policies that decide which mutations to retry.
   * @tparam RPCBackoffPolicy how to backoff from a failed RPC.  Currently only
   *     `ExponentialBackoffPolicy` is implemented. You can also create your
   *     own policies that backoff using a different algorithm.
   * @tparam RPCRetryPolicy for how long to retry failed RPCs. Use
   *     `LimitedErrorCountRetryPolicy` to limit the number of failures allowed.
   *     Use `LimitedTimeRetryPolicy` to bound the time for any request.  You
   *     can also create your own policies that combine time and error counts.
   */
  template <typename RPCRetryPolicy, typename RPCBackoffPolicy,
            typename IdempotentMutationPolicy>
  Table(std::shared_ptr<DataClient> client, std::string const& table_id,
        RPCRetryPolicy retry_policy, RPCBackoffPolicy backoff_policy,
        IdempotentMutationPolicy idempotent_mutation_policy)
      : client_(std::move(client)),
        table_name_(TableName(client_, table_id)),
        rpc_retry_policy_(retry_policy.clone()),
        rpc_backoff_policy_(backoff_policy.clone()),
        metadata_update_policy_(table_name(), MetadataParamTypes::TABLE_NAME),
        idempotent_mutation_policy_(idempotent_mutation_policy.clone()) {}

  std::string const& table_name() const { return table_name_; }

  /**
   * Attempts to apply the mutation to a row.
   *
   * @param mut the mutation. Note that this function takes ownership (and
   *     then discards) the data in the mutation.  In general, a
   *     `SingleRowMutation` can be used to modify and/or delete multiple cells,
   *     across different columns and column families.
   *
   * @throws PermanentMutationFailure if the function cannot
   *     successfully apply the mutation given the current policies. The
   *     exception contains a copy of the original mutation, in case the
   *     application wants to retry, log, or otherwise handle the failure.
   */
  void Apply(SingleRowMutation&& mut);

  /**
   * Attempts to apply mutations to multiple rows.
   *
   * @param mut the mutations, note that this function takes
   *     ownership (and then discards) the data in the mutation. In general, a
   *     `BulkMutation` can modify multiple rows, and the modifications for each
   *     row can change (or create) multiple cells, across different columns and
   *     column families.
   *
   * @throws PermanentMutationFailure based on how the retry policy
   *     handles error conditions.  Note that not idempotent mutations that
   *     are not reported as successful or failed by the server are not sent
   *     to the server more than once, and are reported back with a OK status
   *     in the exception. The exception contains a copy of the original
   *     mutations, in case the application wants to retry, log, or otherwise
   *     handle the failed mutations.
   */
  void BulkApply(BulkMutation&& mut);

  /**
   * Reads a set of rows from the table.
   *
   * @param row_set the rows to read from.
   * @param filter is applied on the server-side to data in the rows.
   */
  RowReader ReadRows(RowSet row_set, Filter filter);

  /**
   * Reads a limited set of rows from the table.
   *
   * @param row_set the rows to read from.
   * @param rows_limit the maximum number of rows to read. Must be larger than
   *     zero. Use `ReadRows(RowSet, Filter)` to read all matching rows.
   * @param filter is applied on the server-side to data in the rows.
   *
   * @throws std::invalid_argument if rows_limit is <= 0.
   */
  RowReader ReadRows(RowSet row_set, std::int64_t rows_limit, Filter filter);

  /**
   * Read and return a single row from the table.
   *
   * @param row_key the row to read.
   * @param filter a filter expression, can be used to select a subset of the
   *     column families and columns in the row.
   * @returns a tuple, the first element is a boolean, with value `false` if the
   *     row does not exist.  If the first element is `true` the second element
   *     has the contents of the Row.  Note that the contents may be empty
   *     if the filter expression removes all column families and columns.
   */
  std::pair<bool, Row> ReadRow(std::string row_key, Filter filter);

  /**
   * Atomic test-and-set for a row using filter expressions.
   *
   * Atomically check the value of a row using a filter expression.  If the
   * expression passes (meaning at least one element is returned by it), one
   * set of mutations is applied.  If the filter does not pass, a different set
   * of mutations is applied.  The changes are atomically applied in the server.
   *
   * @param row_key the row to modify.
   * @param filter the filter expression.
   * @param true_mutations the mutations for the "filter passed" case.
   * @param false_mutations the mutations for the "filter did not pass" case.
   * @returns true if the filter passed.
   */
  bool CheckAndMutateRow(std::string row_key, Filter filter,
                         std::vector<Mutation> true_mutations,
                         std::vector<Mutation> false_mutations);

  /**
  * Sample of the row keys in the table, including approximate data sizes.
  *
  * The application/user can specify the collection type(list and vector
  * supported at this moment), for example:
  * @code
  * auto as_vector = table.SampleRows<std::vector>();
  * auto as_list = table.SampleRows<std::list>();
  * @endcode
  */
  template <template <typename...> class Collection>
  Collection<Table::RowKeySample> SampleRows() {
    Collection<Table::RowKeySample> result;
    SampleRowsImpl(
        [&result](Table::RowKeySample rs) {
          result.emplace_back(std::move(rs));
        },
        [&result]() { result.clear(); });
    return result;
  }

  using RpcUtils = bigtable::internal::UnaryRpcUtils<DataClient>;
  using StubType = RpcUtils::StubType;

  /**
   * Atomically read and modify the row in the server, returning the
   * resulting row
   *
   * @tparam Args this is zero or more ReadModifyWriteRules to apply on a row
   * @param row_key the row to read
   * @param rule to modify the row. Two types of rules are applied here
   *     AppendValue which will read the existing value and append the
   *     text provided to the value.
   *     IncrementAmount which will read the existing uint64 big-endian-int
   *     and add the value provided.
   *     Both rules accept the family and column identifier to modify.
   * @param rules is the zero or more ReadModifyWriteRules to apply on a row.
   * @returns modified row
   */
  template <typename... Args>
  Row ReadModifyWriteRow(std::string row_key,
                         bigtable::ReadModifyWriteRule rule, Args&&... rules) {
    ::google::bigtable::v2::ReadModifyWriteRowRequest request;
    request.set_table_name(table_name_);
    request.set_row_key(std::move(row_key));

    // Generate a better compile time error message than the default one
    // if the types do not match
    static_assert(
        internal::conjunction<
            std::is_convertible<Args, bigtable::ReadModifyWriteRule>...>::value,
        "The arguments passed to ReadModifyWriteRow(row_key,...) must be "
        "convertible to bigtable::ReadModifyWriteRule");

    // TODO(#336) - optimize this code by not copying the parameter pack.
    // Add first default rule
    *request.add_rules() = rule.as_proto_move();
    // Add if any additional rule is present
    std::initializer_list<bigtable::ReadModifyWriteRule> rule_list{
        std::forward<Args>(rules)...};
    for (auto args_rule : rule_list) {
      *request.add_rules() = args_rule.as_proto_move();
    }

    return CallReadModifyWriteRowRequest(request);
  }

 private:
  /**
   * Send request ReadModifyWriteRowRequest to modify the row and get it back
   */
  Row CallReadModifyWriteRowRequest(
      ::google::bigtable::v2::ReadModifyWriteRowRequest request);

  /**
   * Refactor implementation to `.cc` file.
   *
   * Provides a compilation barrier so that the application is not
   * exposed to all the implementation details.
   *
   * @param inserter Function to insert the object to result.
   * @param clearer Function to clear the result object if RPC fails.
   */
  void SampleRowsImpl(std::function<void(Table::RowKeySample)> inserter,
                      std::function<void()> clearer);

  std::shared_ptr<DataClient> client_;
  std::string table_name_;
  std::unique_ptr<RPCRetryPolicy> rpc_retry_policy_;
  std::unique_ptr<RPCBackoffPolicy> rpc_backoff_policy_;
  MetadataUpdatePolicy metadata_update_policy_;
  std::unique_ptr<IdempotentMutationPolicy> idempotent_mutation_policy_;
};

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_TABLE_H_
