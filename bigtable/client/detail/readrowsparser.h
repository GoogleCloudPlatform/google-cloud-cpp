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

#ifndef GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_DETAIL_READROWSPARSER_H_
#define GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_DETAIL_READROWSPARSER_H_

#include "bigtable/client/version.h"

#include "bigtable/client/cell.h"
#include "bigtable/client/row.h"

#include "google/bigtable/v2/bigtable.grpc.pb.h"

#include <absl/strings/string_view.h>
#include <vector>

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Transforms a stream of chunks as returned by the ReadRows streaming
 * RPC into a sequence of rows.
 *
 * Users are expected to do something like:
 *
 * @code
 * while (!stream.EOT()) {
 *   chunk = stream.NextChunk();
 *   parser.HandleChunk(chunk);
 *   if (parser.HasNext()) {
 *     row = parser.Next();  // you now own `row`
 *   }
 * }
 * parser.HandleEOT();
 * @endcode
 */
class ReadRowsParser {
 public:
  ReadRowsParser()
      : row_key_(""),
        cells_(),
        cell_first_chunk_(true),
        cell_(),
        last_seen_row_key_(""),
        row_ready_(false),
        eot_(false) {}

  /**
   * Pass an input chunk proto to the parser.
   *
   * @throws std::runtime_error if called while a row is available
   * (HasNext() is true).
   *
   * @throws std::runtime_error if validation failed.
   */
  void HandleChunk(google::bigtable::v2::ReadRowsResponse_CellChunk chunk);

  /**
   * Signal that the input stream reached the end.
   *
   * @throws std::runtime_error if more data was expected.
   */
  void HandleEOT();

  /**
   * True if the data parsed so far yielded a Row.
   *
   * Call Next() to take the row.
   */
  bool HasNext() const;

  /**
   * Extract and take ownership of the data in a row.
   *
   * Use HasNext() first to find out if there are rows available.
   *
   * @throws std::runtime_error if HasNext() is false.
   */
  Row Next();

 private:
  /// Holds partially formed data until a full Row is ready.
  struct ParseCell {
    std::string row;
    std::string family;
    std::string column;
    int64_t timestamp;
    std::string value;
    std::vector<std::string> labels;
  };

  /*
   * Moves partial results into a Cell class.
   *
   * Also helps handle string ownership correctly. The value is moved
   * when converting to a result cell, but the key, family and column
   * are copied, because they are possibly reused by following cells.
   */
  Cell MovePartialToCell();

  /// Row key for the current row.
  std::string row_key_;

  /// Parsed cells of a yet unfinished row.
  std::vector<Cell> cells_;

  /// Is the next incoming chunk the first in a cell?
  bool cell_first_chunk_;

  /// Stores partial fields.
  ParseCell cell_;

  /// Set when a row is ready.
  std::string last_seen_row_key_;

  /// True iff cells_ make up a complete row.
  bool row_ready_;

  /// Have we received EOT?
  bool eot_;
};

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_DETAIL_READROWSPARSER_H_
