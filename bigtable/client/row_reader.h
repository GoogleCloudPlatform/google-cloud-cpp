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

#ifndef GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_ROW_READER_H_
#define GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_ROW_READER_H_

#include "bigtable/client/version.h"

#include "bigtable/client/data_client.h"
#include "bigtable/client/filters.h"
#include "bigtable/client/internal/readrowsparser.h"
#include "bigtable/client/internal/rowreaderiterator.h"
#include "bigtable/client/row.h"
#include "bigtable/client/row_set.h"
#include "bigtable/client/rpc_backoff_policy.h"
#include "bigtable/client/rpc_retry_policy.h"

#include <google/bigtable/v2/bigtable.grpc.pb.h>

#include <absl/memory/memory.h>
#include <absl/types/optional.h>
#include <grpc++/grpc++.h>

#include <cinttypes>
#include <iterator>

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Object returned by Table::ReadRows(), enumerates rows in the response.
 *
 * Iterate over the results of ReadRows() using the STL idioms.
 */
class RowReader {
 public:
  /**
   * A constant for the magic value that means "no limit, get all rows".
   *
   * Zero is used as a magic value that means "get all rows" in the
   * Cloud Bigtable RPC protocol.
   */
  static std::int64_t constexpr NO_ROWS_LIMIT = 0;

  RowReader(std::shared_ptr<DataClient> client, absl::string_view table_name,
            RowSet row_set, std::int64_t rows_limit, Filter filter,
            std::unique_ptr<RPCRetryPolicy> retry_policy,
            std::unique_ptr<RPCBackoffPolicy> backoff_policy,
            std::unique_ptr<internal::ReadRowsParser> parser);

  using iterator = internal::RowReaderIterator;
  friend class internal::RowReaderIterator;

  /**
   * Input iterator over rows in the response.
   *
   * The returned iterator is a single-pass input iterator that reads
   * rows from the RowReader when incremented. The first row may be
   * read when the iterator is constructed.
   *
   * Creating, and particularly incrementing, multiple iterators on
   * the same RowReader is unsupported and can produce incorrect
   * results.
   *
   * Retry and backoff policies are honored.
   *
   * @throws std::runtime_error if the read failed after retries.
   */
  iterator begin();

  /// End iterator over the rows in the response.
  iterator end();

  /**
   * Gracefully terminate a streaming read.
   *
   * Invalidates iterators.
   */
  void Cancel();

 private:
  /**
   * Read and parse the next row in the response.
   *
   * @param row receives the next row on success, and is reset on failure or if
   * there are no more rows.
   *
   * This call possibly blocks waiting for data until a full row is available.
   */
  void Advance(absl::optional<Row>& row);

  /// Called by Advance(), does not handle retries.
  grpc::Status AdvanceOrFail(absl::optional<Row>& row);

  /**
   * Move the `processed_chunks_count_` index to the next chunk,
   * reading data if needed.
   *
   * Returns false if no more chunks are available.
   *
   * This call is used internally by AdvanceOrFail to prepare data for
   * parsing. When it returns true, the value of
   * `response_.chunks(processed_chunks_count_)` is valid and holds
   * the next chunk to parse.
   */
  bool NextChunk();

  /// Sends the ReadRows request to the stub.
  void MakeRequest();

  std::shared_ptr<DataClient> client_;
  std::string table_name_;
  RowSet row_set_;
  std::int64_t rows_limit_;
  Filter filter_;
  std::unique_ptr<RPCRetryPolicy> retry_policy_;
  std::unique_ptr<RPCBackoffPolicy> backoff_policy_;

  std::unique_ptr<grpc::ClientContext> context_;

  std::unique_ptr<internal::ReadRowsParser> parser_;
  std::unique_ptr<
      grpc::ClientReaderInterface<google::bigtable::v2::ReadRowsResponse>>
      stream_;

  /// The last received response, chunks are being parsed one by one from it.
  google::bigtable::v2::ReadRowsResponse response_;
  /// Number of chunks already parsed in response_.
  int processed_chunks_count_;

  /// Number of rows read so far, used to set row_limit in retries.
  std::int64_t rows_count_;
  /// Holds the last read row key, for retries.
  std::string last_read_row_key_;
};

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_ROW_READER_H_
