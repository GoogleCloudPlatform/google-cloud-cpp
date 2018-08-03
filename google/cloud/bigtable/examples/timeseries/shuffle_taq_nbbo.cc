// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "taq.pb.h"
#include "google/cloud/bigtable/admin_client.h"
#include "google/cloud/bigtable/data_client.h"
#include "google/cloud/bigtable/table.h"
#include "google/cloud/bigtable/table_admin.h"
#include <chrono>
#include <cmath>
#include <fstream>
#include <future>
#include <iomanip>
#include <sstream>

/**
 * @file
 *
 * This example shows a simple ETL process between two tables with timeseries
 * data.
 *
 * The input for this example is the table generated by `upload_taq_nbbo.cc`.
 * The row keys in this table should be in `SYMBOL#YYYYMMDD#TIMESTAMP` format,
 * the `parsed` column family contains a `nbbo` column, the values of these
 * column are serialized `taq.Quote` protos.
 *
 * This example reads the data from this table and produces a new table with a
 * single row for each symbol, and all the quotes in a single column with a
 * serialized `taq.QuoteSequence` proto.
 */

/// Helper functions used in the shuffle_taq_nbbo example.
namespace {
namespace cbt = google::cloud::bigtable;

/// Shuffle the symbols in the range [@p begin, @p end).
void Shuffle(cbt::Table& input, cbt::Table& output, std::string begin,
             std::string end);
}  // anonymous namespace

int main(int argc, char* argv[]) try {
  // Make sure we have the right number of arguments.
  if (argc != 4) {
    std::string const cmd = argv[0];
    auto last_slash = std::string(argv[0]).find_last_of('/');
    std::cerr << "Usage: " << cmd.substr(last_slash + 1)
              << " <project> <instance> <input_table_id>" << std::endl;
    return 1;
  }
  std::string const project_id = argv[1];
  std::string const instance_id = argv[2];
  std::string const input_table_id = "taq-quotes";
  std::string const output_table_id = "shuffled-data";

  cbt::Table input(cbt::CreateDefaultDataClient(project_id, instance_id,
                                                cbt::ClientOptions()),
                   input_table_id);

  // These magical splits are "known" to be good splits for US market data.
  // Look at the estimate_splits_points.cc program to see how these can be
  // calculated efficiently.
  std::vector<std::string> splits{
      "AG", "AS", "BH", "CA", "CM", "CT", "DK", "EF", "EW", "FI", "FX",
      "GP", "HR", "IN", "JC", "LA", "MA", "MR", "NO", "OR", "PN", "QS",
      "SA", "SM", "SS", "TG", "TV", "US", "VO", "WL", "XL",
  };
  using namespace std::chrono;

  cbt::TableAdmin admin(
      cbt::CreateDefaultAdminClient(project_id, cbt::ClientOptions()),
      instance_id);
  try {
    auto gc = cbt::GcRule::MaxNumVersions(1);
    auto table_schema = admin.CreateTable(
        output_table_id, cbt::TableConfig({{"taq", gc}}, splits));
    std::cout << "Created output table\n";
  } catch (std::exception const& ex) {
    // Ignore exception because they often happen because the table already
    // exists.
    // TODO(#119) - fix the code here to ignore only the right exception.
    std::cout << "Output table already exists\n";
  }

  cbt::Table output(cbt::CreateDefaultDataClient(project_id, instance_id,
                                                 cbt::ClientOptions()),
                    output_table_id);

  // Artificially enter an initial and final value into the splits to represent
  // "lowest possible value" and "highest possible value".
  splits.insert(splits.begin(), "");
  splits.emplace_back("");

  // Shuffle the symbols between each split point using a separate thread.
  auto work = [&input, &output](std::string begin, std::string end) {
    Shuffle(input, output, std::move(begin), std::move(end));
  };
  std::cout << "Executing parallel shuffle " << std::flush;
  auto start = steady_clock::now();
  std::vector<std::future<void>> tasks;
  for (std::size_t i = 0; i != splits.size() - 1; ++i) {
    tasks.emplace_back(
        std::async(std::launch::async, work, splits[i], splits[i + 1]));
  }
  int task = 0;
  for (auto& t : tasks) {
    try {
      t.get();
    } catch (std::exception const& ex) {
      std::cerr << "Exception raised by task [" << task << "]: " << ex.what()
                << std::endl;
    }
    ++task;
  }

  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::steady_clock::now() - start);
  std::cout << " DONE in " << elapsed.count() << "s" << std::endl;

  return 0;
} catch (std::exception const& ex) {
  std::cerr << "Standard exception raised: " << ex.what() << std::endl;
  return 1;
}

namespace {
void Shuffle(cbt::Table& input, cbt::Table& output, std::string begin,
             std::string end) {
  long symbol_count = 0;
  using F = cbt::Filter;
  auto reader = input.ReadRows(
      cbt::RowSet(cbt::RowRange::Range(std::move(begin), std::move(end))),
      F::ColumnRangeClosed("parsed", "nbbo", "nbbo"));
  std::string current_key;
  taq::QuoteSequence current_quotes;
  for (auto const& row : reader) {
    std::istringstream tokens(row.row_key());
    tokens.exceptions(std::ios::failbit);

    std::string symbol;
    std::getline(tokens, symbol, '#');
    std::string yyyymmdd;
    std::getline(tokens, yyyymmdd, '#');
    std::string timestamp;
    std::getline(tokens, timestamp);

    auto hh = std::stoi(timestamp.substr(0, 2));
    auto mm = std::stoi(timestamp.substr(2, 2));
    auto ss = std::stoi(timestamp.substr(4, 2));
    auto nnn = std::stol(timestamp.substr(6));
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::hours(hh) + std::chrono::minutes(mm) +
        std::chrono::seconds(ss) + std::chrono::nanoseconds(nnn));

    // Because ReadRows() iterates in order, and the rows for the same symbol
    // are consecutive we know that when a new symbol appears it is time to
    // flush it.
    std::string key = symbol + "#" + yyyymmdd;
    if (key != current_key) {
      if (not current_key.empty()) {
        cbt::SingleRowMutation mutation(current_key);
        mutation.emplace_back(cbt::SetCell("taq", "quotes",
                                           std::chrono::milliseconds(0),
                                           current_quotes.SerializeAsString()));
        output.Apply(std::move(mutation));
      }
      ++symbol_count;
      if (symbol_count % 100 == 0) {
        std::cout << "." << std::flush;
      }
      current_quotes = {};
      current_key = key;
    }
    for (auto const& cell : row.cells()) {
      if (cell.family_name() != "parsed" or cell.column_qualifier() != "nbbo") {
        continue;
      }
      taq::Quote nbbo;
      nbbo.ParseFromString(cell.value());
      current_quotes.add_timestamp(nanos.count());
      current_quotes.add_bid_exchange_code(nbbo.bid_exchange_code());
      current_quotes.add_bid_price(nbbo.bid_price());
      current_quotes.add_bid_size(nbbo.bid_size());
      current_quotes.add_offer_exchange_code(nbbo.offer_exchange_code());
      current_quotes.add_offer_price(nbbo.offer_price());
      current_quotes.add_offer_size(nbbo.offer_size());
    }
  }
  // Do not forget to flush the last symbol.
  if (current_key.empty()) {
    return;
  }
  cbt::SingleRowMutation mutation(current_key);
  mutation.emplace_back(cbt::SetCell("taq", "quotes",
                                     std::chrono::milliseconds(0),
                                     current_quotes.SerializeAsString()));
  output.Apply(std::move(mutation));
}

}  // anonymous namespace
