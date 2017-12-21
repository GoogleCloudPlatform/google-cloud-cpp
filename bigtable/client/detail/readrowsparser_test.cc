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

#include "bigtable/client/detail/readrowsparser.h"

#include <absl/strings/str_join.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>

#include <numeric>
#include <sstream>
#include <vector>

using google::bigtable::v2::ReadRowsResponse_CellChunk;

namespace bigtable {
namespace {

// Can also be used by gtest to print Cell values
void PrintTo(Cell const& c, std::ostream* os) {
  *os << "rk: " << std::string(c.row_key()) << "\n";
  *os << "fm: " << std::string(c.family_name()) << "\n";
  *os << "qual: " << std::string(c.column_qualifier()) << "\n";
  *os << "ts: " << c.timestamp() << "\n";
  *os << "value: " << std::string(c.value()) << "\n";
  *os << "label: " << absl::StrJoin(c.labels(), ",") << "\n";
}

std::string CellToString(Cell const& cell) {
  std::stringstream ss;
  PrintTo(cell, &ss);
  return ss.str();
}

}  // namespace
}  // namespace bigtable

class AcceptanceTest : public ::testing::Test {
 protected:
  std::vector<std::string> ExtractCells() {
    std::vector<std::string> cells;

    for (auto const& r : rows_) {
      std::transform(r.cells().begin(), r.cells().end(),
                     std::back_inserter(cells), bigtable::CellToString);
    }
    return cells;
  }

  std::vector<ReadRowsResponse_CellChunk> ConvertChunks(
      std::vector<std::string> chunk_strings) {
    using google::protobuf::TextFormat;

    std::vector<ReadRowsResponse_CellChunk> chunks;
    for (std::string const& chunk_string : chunk_strings) {
      ReadRowsResponse_CellChunk chunk;
      if (not TextFormat::ParseFromString(chunk_string, &chunk)) {
        return {};
      }
      chunks.emplace_back(std::move(chunk));
    }

    return chunks;
  }

  void FeedChunks(std::vector<ReadRowsResponse_CellChunk> chunks) {
    for (auto const& chunk : chunks) {
      parser_.HandleChunk(chunk);
      if (parser_.HasNext()) {
        rows_.emplace_back(parser_.Next());
      }
    }
    parser_.HandleEOT();
  }

 private:
  bigtable::ReadRowsParser parser_;
  std::vector<bigtable::Row> rows_;
};

// The tests included between the markers below are defined in the
// file "read-rows-acceptance-test.json" in the cloud-bigtable-client
// repository and formatted as C++ code using tools/convert_tests.py

// **** AUTOMATICALLY GENERATED ACCEPTANCE TESTS BEGIN HERE ****

// Test name: "invalid - no commit"
TEST_F(AcceptanceTest, InvalidNoCommit) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - no cell key before commit"
TEST_F(AcceptanceTest, InvalidNoCellKeyBeforeCommit) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - no cell key before value"
TEST_F(AcceptanceTest, InvalidNoCellKeyBeforeValue) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - new col family must specify qualifier"
TEST_F(AcceptanceTest, InvalidNewColFamilyMustSpecifyQualifier) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          family_name: < value: "B">
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "bare commit implies ts=0"
TEST_F(AcceptanceTest, BareCommitImpliesTs) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: \n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "simple row with timestamp"
TEST_F(AcceptanceTest, SimpleRowWithTimestamp) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "missing timestamp, implied ts=0"
TEST_F(AcceptanceTest, MissingTimestampImpliedTs) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "empty cell value"
TEST_F(AcceptanceTest, EmptyCellValue) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: \n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two unsplit cells"
TEST_F(AcceptanceTest, TwoUnsplitCells) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two qualifiers"
TEST_F(AcceptanceTest, TwoQualifiers) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          qualifier: < value: "D">
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: D\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two families"
TEST_F(AcceptanceTest, TwoFamilies) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          family_name: < value: "B">
          qualifier: < value: "E">
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK\n"
      "fm: B\n"
      "qual: E\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "with labels"
TEST_F(AcceptanceTest, WithLabels) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          labels: "L_1"
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 98
          labels: "L_2"
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: L_1\n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: L_2\n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "split cell, bare commit"
TEST_F(AcceptanceTest, SplitCellBareCommit) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: \n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "split cell"
TEST_F(AcceptanceTest, SplitCell) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "split four ways"
TEST_F(AcceptanceTest, SplitFourWays) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          labels: "L"
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "a"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "l"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "ue-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: L\n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two split cells"
TEST_F(AcceptanceTest, TwoSplitCells) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 98
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "multi-qualifier splits"
TEST_F(AcceptanceTest, MultiqualifierSplits) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          qualifier: < value: "D">
          timestamp_micros: 98
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: D\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "multi-qualifier multi-split"
TEST_F(AcceptanceTest, MultiqualifierMultisplit) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "a"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "lue-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          qualifier: < value: "D">
          timestamp_micros: 98
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "a"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "lue-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: D\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "multi-family split"
TEST_F(AcceptanceTest, MultifamilySplit) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          family_name: < value: "B">
          qualifier: < value: "E">
          timestamp_micros: 98
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK\n"
      "fm: B\n"
      "qual: E\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - no commit between rows"
TEST_F(AcceptanceTest, InvalidNoCommitBetweenRows) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - no commit after first row"
TEST_F(AcceptanceTest, InvalidNoCommitAfterFirstRow) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - last row missing commit"
TEST_F(AcceptanceTest, InvalidLastRowMissingCommit) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - duplicate row key"
TEST_F(AcceptanceTest, InvalidDuplicateRowKey) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "B">
          qualifier: < value: "D">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - new row missing row key"
TEST_F(AcceptanceTest, InvalidNewRowMissingRowKey) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
      R"chunk(
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows"
TEST_F(AcceptanceTest, TwoRows) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows implicit timestamp"
TEST_F(AcceptanceTest, TwoRowsImplicitTimestamp) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          value: "value-VAL"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: value-VAL\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows empty value"
TEST_F(AcceptanceTest, TwoRowsEmptyValue) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: \n"
      "label: \n",

      "rk: RK_2\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows, one with multiple cells"
TEST_F(AcceptanceTest, TwoRowsOneWithMultipleCells) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "B">
          qualifier: < value: "D">
          timestamp_micros: 97
          value: "value-VAL_3"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: B\n"
      "qual: D\n"
      "ts: 97\n"
      "value: value-VAL_3\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows, multiple cells"
TEST_F(AcceptanceTest, TwoRowsMultipleCells) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          qualifier: < value: "D">
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "B">
          qualifier: < value: "E">
          timestamp_micros: 97
          value: "value-VAL_3"
          commit_row: false
        )chunk",
      R"chunk(
          qualifier: < value: "F">
          timestamp_micros: 96
          value: "value-VAL_4"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK_1\n"
      "fm: A\n"
      "qual: D\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: B\n"
      "qual: E\n"
      "ts: 97\n"
      "value: value-VAL_3\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: B\n"
      "qual: F\n"
      "ts: 96\n"
      "value: value-VAL_4\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows, multiple cells, multiple families"
TEST_F(AcceptanceTest, TwoRowsMultipleCellsMultipleFamilies) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          family_name: < value: "B">
          qualifier: < value: "E">
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "M">
          qualifier: < value: "O">
          timestamp_micros: 97
          value: "value-VAL_3"
          commit_row: false
        )chunk",
      R"chunk(
          family_name: < value: "N">
          qualifier: < value: "P">
          timestamp_micros: 96
          value: "value-VAL_4"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK_1\n"
      "fm: B\n"
      "qual: E\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: M\n"
      "qual: O\n"
      "ts: 97\n"
      "value: value-VAL_3\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: N\n"
      "qual: P\n"
      "ts: 96\n"
      "value: value-VAL_4\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows, four cells, 2 labels"
TEST_F(AcceptanceTest, TwoRowsFourCellsLabels) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 99
          labels: "L_1"
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "B">
          qualifier: < value: "D">
          timestamp_micros: 97
          labels: "L_3"
          value: "value-VAL_3"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 96
          value: "value-VAL_4"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 99\n"
      "value: value-VAL_1\n"
      "label: L_1\n",

      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 98\n"
      "value: value-VAL_2\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: B\n"
      "qual: D\n"
      "ts: 97\n"
      "value: value-VAL_3\n"
      "label: L_3\n",

      "rk: RK_2\n"
      "fm: B\n"
      "qual: D\n"
      "ts: 96\n"
      "value: value-VAL_4\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two rows with splits, same timestamp"
TEST_F(AcceptanceTest, TwoRowsWithSplitsSameTimestamp) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_1"
          commit_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "alue-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_1\n"
      "label: \n",

      "rk: RK_2\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - bare reset"
TEST_F(AcceptanceTest, InvalidBareReset) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          reset_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - bad reset, no commit"
TEST_F(AcceptanceTest, InvalidBadResetNoCommit) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - missing key after reset"
TEST_F(AcceptanceTest, InvalidMissingKeyAfterReset) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "no data after reset"
TEST_F(AcceptanceTest, NoDataAfterReset) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "simple reset"
TEST_F(AcceptanceTest, SimpleReset) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "reset to new val"
TEST_F(AcceptanceTest, ResetToNewVal) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "reset to new qual"
TEST_F(AcceptanceTest, ResetToNewQual) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "D">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: D\n"
      "ts: 100\n"
      "value: value-VAL_1\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "reset with splits"
TEST_F(AcceptanceTest, ResetWithSplits) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 98
          value: "value-VAL_2"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "reset two cells"
TEST_F(AcceptanceTest, ResetTwoCells) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_2"
          commit_row: false
        )chunk",
      R"chunk(
          timestamp_micros: 97
          value: "value-VAL_3"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_2\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 97\n"
      "value: value-VAL_3\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "two resets"
TEST_F(AcceptanceTest, TwoResets) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_2"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_3"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_3\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "reset then two cells"
TEST_F(AcceptanceTest, ResetThenTwoCells) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK"
          family_name: < value: "B">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_2"
          commit_row: false
        )chunk",
      R"chunk(
          qualifier: < value: "D">
          timestamp_micros: 97
          value: "value-VAL_3"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: B\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_2\n"
      "label: \n",

      "rk: RK\n"
      "fm: B\n"
      "qual: D\n"
      "ts: 97\n"
      "value: value-VAL_3\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "reset to new row"
TEST_F(AcceptanceTest, ResetToNewRow) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK_2"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_2"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_2\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_2\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "reset in between chunks"
TEST_F(AcceptanceTest, ResetInBetweenChunks) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          labels: "L"
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "a"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          reset_row: true
        )chunk",
      R"chunk(
          row_key: "RK_1"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL_1"
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK_1\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL_1\n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - reset with chunk"
TEST_F(AcceptanceTest, InvalidResetWithChunk) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          labels: "L"
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "a"
          value_size: 10
          reset_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "invalid - commit with chunk"
TEST_F(AcceptanceTest, InvalidCommitWithChunk) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          labels: "L"
          value: "v"
          value_size: 10
          commit_row: false
        )chunk",
      R"chunk(
          value: "a"
          value_size: 10
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_THROW(FeedChunks(chunks), std::exception);

  std::vector<std::string> expected_cells = {};
  EXPECT_EQ(expected_cells, ExtractCells());
}

// Test name: "empty cell chunk"
TEST_F(AcceptanceTest, EmptyCellChunk) {
  std::vector<std::string> chunk_strings = {
      R"chunk(
          row_key: "RK"
          family_name: < value: "A">
          qualifier: < value: "C">
          timestamp_micros: 100
          value: "value-VAL"
          commit_row: false
        )chunk",
      R"chunk(
          commit_row: false
        )chunk",
      R"chunk(
          commit_row: true
        )chunk",
  };

  auto chunks = ConvertChunks(std::move(chunk_strings));
  ASSERT_FALSE(chunks.empty());

  EXPECT_NO_THROW(FeedChunks(chunks));

  std::vector<std::string> expected_cells = {
      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 100\n"
      "value: value-VAL\n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: \n"
      "label: \n",

      "rk: RK\n"
      "fm: A\n"
      "qual: C\n"
      "ts: 0\n"
      "value: \n"
      "label: \n",
  };
  EXPECT_EQ(expected_cells, ExtractCells());
}

// **** AUTOMATICALLY GENERATED ACCEPTANCE TESTS END HERE ****
