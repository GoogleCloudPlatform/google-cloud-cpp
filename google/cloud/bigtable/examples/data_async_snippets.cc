// Copyright 2019 Google LLC
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

//! [all code]

//! [bigtable includes]
#include "google/cloud/bigtable/internal/table.h"
#include "google/cloud/bigtable/table.h"
//! [bigtable includes]
#include <google/protobuf/text_format.h>
#include <sstream>

namespace {
const std::string MAGIC_ROW_KEY = "key-000005";

struct Usage {
  std::string msg;
};

std::string command_usage;

void PrintUsage(std::string const& cmd, std::string const& msg) {
  auto last_slash = std::string(cmd).find_last_of('/');
  auto program = cmd.substr(last_slash + 1);
  std::cerr << msg << "\nUsage: " << program << " <command> [arguments]\n\n"
            << "Commands:\n"
            << command_usage << "\n";
}

void AsyncApply(google::cloud::bigtable::Table table,
                google::cloud::bigtable::CompletionQueue cq,
                std::vector<std::string> argv) {
  if (argv.size() != 2U) {
    throw Usage{"async-apply: <project-id> <instance-id> <table-id>"};
  }

  //! [async-apply]
  namespace cbt = google::cloud::bigtable;
  [](cbt::Table table, cbt::CompletionQueue cq, std::string table_id) {
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch());

    cbt::SingleRowMutation mutation("test-key-for-async-apply");
    mutation.emplace_back(cbt::SetCell("fam", "some-column", "some-value"));
    mutation.emplace_back(
        cbt::SetCell("fam", "another-column", "another-value"));
    mutation.emplace_back(cbt::SetCell("fam", "even-more-columns", timestamp,
                                       "with-explicit-timestamp"));

    google::cloud::future<google::cloud::Status> fut =
        table.AsyncApply(std::move(mutation), cq);
    google::cloud::Status status = fut.get();
    if (!status.ok()) {
      throw std::runtime_error(status.message());
    }
    std::cout << "Successfully applied mutation\n";
  }
  //! [async-apply]
  (std::move(table), std::move(cq), argv[1]);
}

void AsyncBulkApply(google::cloud::bigtable::Table table,
                    google::cloud::bigtable::CompletionQueue cq,
                    std::vector<std::string> argv) {
  if (argv.size() != 2U) {
    throw Usage{"async-bulk-apply: <project-id> <instance-id> <table-id>"};
  }

  //! [bulk async-bulk-apply]
  namespace cbt = google::cloud::bigtable;
  [](cbt::Table table, cbt::CompletionQueue cq, std::string table_id) {
    // Write several rows in a single operation, each row has some trivial data.
    cbt::BulkMutation bulk;
    for (int i = 0; i != 5000; ++i) {
      // Note: This example uses sequential numeric IDs for simplicity, but
      // this can result in poor performance in a production application.
      // Since rows are stored in sorted order by key, sequential keys can
      // result in poor distribution of operations across nodes.
      //
      // For more information about how to design a Bigtable schema for the
      // best performance, see the documentation:
      //
      //     https://cloud.google.com/bigtable/docs/schema-design
      char buf[32];
      snprintf(buf, sizeof(buf), "key-%06d", i);
      cbt::SingleRowMutation mutation(buf);
      mutation.emplace_back(
          cbt::SetCell("fam", "col0", "value0-" + std::to_string(i)));
      mutation.emplace_back(
          cbt::SetCell("fam", "col1", "value2-" + std::to_string(i)));
      mutation.emplace_back(
          cbt::SetCell("fam", "col2", "value3-" + std::to_string(i)));
      mutation.emplace_back(
          cbt::SetCell("fam", "col3", "value4-" + std::to_string(i)));
      bulk.emplace_back(std::move(mutation));
    }

    google::cloud::future<std::vector<cbt::FailedMutation>> fut =
        table.AsyncBulkApply(std::move(bulk), cq);

    fut.get();
  }
  //! [bulk async-bulk-apply]
  (std::move(table), std::move(cq), argv[1]);
}

void AsyncReadRows(google::cloud::bigtable::Table table,
                   google::cloud::bigtable::CompletionQueue cq,
                   std::vector<std::string> argv) {
  if (argv.size() != 2U) {
    throw Usage{"read-rows: <project-id> <instance-id> <table-id>"};
  }

  //! [async read rows]
  namespace cbt = google::cloud::bigtable;
  using google::cloud::optional;
  using google::cloud::StatusOr;
  [](cbt::CompletionQueue cq, cbt::Table table) {
    // Create the range of rows to read.
    auto range = cbt::RowRange::Range("key-000010", "key-000020");
    // Filter the results, only include values from the "col0" column in the
    // "fam" column family, and only get the latest value.
    auto filter = cbt::Filter::Chain(
        cbt::Filter::ColumnRangeClosed("fam", "col0", "col0"),
        cbt::Filter::Latest(1));
    // Read and print the rows.
    auto reader = table.AsyncReadRows(cq, range, filter);
    StatusOr<optional<cbt::Row>> row;
    // Normally the user would not synchronously wait for the rows, but most
    // likely use `.then()` to chain obtaining new rows instead. This is just
    // for illustration.
    for (row = reader->Next().get(); row && row->has_value();
         row = reader->Next().get()) {
      if ((*row)->cells().size() != 1) {
        std::ostringstream os;
        os << "Unexpected number of cells in " << (*row)->row_key();
        throw std::runtime_error(os.str());
      }
      auto const& cell = (*row)->cells().at(0);
      std::cout << cell.row_key() << " = [" << cell.value() << "]\n";
    }
    std::cout << std::flush;
    if (!row) {
      throw std::runtime_error(row.status().message());
    }
  }
  //! [async read rows]
  (std::move(cq), std::move(table));
}

void AsyncReadRowsWithLimit(google::cloud::bigtable::Table table,
                            google::cloud::bigtable::CompletionQueue cq,
                            std::vector<std::string> argv) {
  if (argv.size() != 2U) {
    throw Usage{"read-rows: <project-id> <instance-id> <table-id>"};
  }

  //! [async read rows with limit]
  namespace cbt = google::cloud::bigtable;
  using google::cloud::optional;
  using google::cloud::StatusOr;
  [](cbt::CompletionQueue cq, cbt::Table table) {
    // Create the range of rows to read.
    auto range = cbt::RowRange::Range("key-000010", "key-000020");
    // Filter the results, only include values from the "col0" column in the
    // "fam" column family, and only get the latest value.
    auto filter = cbt::Filter::Chain(
        cbt::Filter::ColumnRangeClosed("fam", "col0", "col0"),
        cbt::Filter::Latest(1));
    // Read and print the rows.
    auto reader = table.AsyncReadRows(cq, range, 5, filter);
    StatusOr<optional<cbt::Row>> row;
    // Normally the user would not synchronously wait for the rows, but most
    // likely use `.then()` to chain obtaining new rows instead. This is just
    // for illustration.
    for (row = reader->Next().get(); row && row->has_value();
         row = reader->Next().get()) {
      if ((*row)->cells().size() != 1) {
        std::ostringstream os;
        os << "Unexpected number of cells in " << (*row)->row_key();
        throw std::runtime_error(os.str());
      }
      auto const& cell = (*row)->cells().at(0);
      std::cout << cell.row_key() << " = [" << cell.value() << "]\n";
    }
    std::cout << std::flush;
    if (!row) {
      throw std::runtime_error(row.status().message());
    }
  }
  //! [async read rows with limit]
  (std::move(cq), std::move(table));
}

void AsyncCheckAndMutate(google::cloud::bigtable::Table table,
                         google::cloud::bigtable::CompletionQueue cq,
                         std::vector<std::string> argv) {
  if (argv.size() != 2U) {
    throw Usage{
        "async-check-and-mutate: <project-id> <instance-id> <table-id>"};
  }

  //! [async check and mutate]
  namespace cbt = google::cloud::bigtable;
  [](cbt::Table table, cbt::CompletionQueue cq, std::string table_id) {
    // Check if the latest value of the flip-flop column is "on".
    auto predicate = cbt::Filter::Chain(
        cbt::Filter::ColumnRangeClosed("fam", "flip-flop", "flip-flop"),
        cbt::Filter::Latest(1), cbt::Filter::ValueRegex("on"));
    google::cloud::future<google::cloud::StatusOr<
        google::bigtable::v2::CheckAndMutateRowResponse>>
        future = table.AsyncCheckAndMutateRow(
            MAGIC_ROW_KEY, std::move(predicate),
            {cbt::SetCell("fam", "flip-flop", "off"),
             cbt::SetCell("fam", "flop-flip", "on")},
            {cbt::SetCell("fam", "flip-flop", "on"),
             cbt::SetCell("fam", "flop-flip", "off")},
            cq);

    auto final =
        future.then([](google::cloud::future<google::cloud::StatusOr<
                           google::bigtable::v2::CheckAndMutateRowResponse>>
                           f) {
          auto row = f.get();
          if (!row) {
            throw std::runtime_error(row.status().message());
          }

          return google::cloud::Status();
        });
    final.get();
  }
  //! [async check and mutate]
  (std::move(table), std::move(cq), argv[1]);
}

void AsyncReadModifyWrite(google::cloud::bigtable::Table table,
                          google::cloud::bigtable::CompletionQueue cq,
                          std::vector<std::string> argv) {
  // TODO(#2404) - remove hard-coded key values
  if (argv.size() != 2U) {
    throw Usage{
        "async-read-modify-write: <project-id> <instance-id> <table-id>"};
  }

  //! [async read modify write]
  namespace cbt = google::cloud::bigtable;
  using google::cloud::future;
  using google::cloud::StatusOr;
  [](cbt::Table table, cbt::CompletionQueue cq, std::string table_id,
     std::string row_key) {
    future<StatusOr<cbt::Row>> async_future = table.AsyncReadModifyWriteRow(
        row_key, cq,
        cbt::ReadModifyWriteRule::AppendValue("fam", "list", ";element"));

    auto final =
        async_future.then([](future<google::cloud::StatusOr<cbt::Row>> f) {
          auto row = f.get();
          if (!row) {
            throw std::runtime_error(row.status().message());
          }
        });

    final.get();
  }
  //! [async read modify write]
  (std::move(table), std::move(cq), argv[1], MAGIC_ROW_KEY);
}
}  // anonymous namespace

int main(int argc, char* argv[]) try {
  using CommandType = std::function<void(
      google::cloud::bigtable::Table, google::cloud::bigtable::CompletionQueue,
      std::vector<std::string>)>;

  std::map<std::string, CommandType> commands = {
      {"async-apply", &AsyncApply},
      {"async-bulk-apply", &AsyncBulkApply},
      {"async-read-rows", &AsyncReadRows},
      {"async-read-rows-with-limit", &AsyncReadRowsWithLimit},
      {"async-check-and-mutate", &AsyncCheckAndMutate},
      {"async-read-modify-write", &AsyncReadModifyWrite}};

  google::cloud::bigtable::CompletionQueue cq;

  {
    // Force each command to generate its Usage string, so we can provide a good
    // usage string for the whole program. We need to create an Table
    // object to do this, but that object is never used, it is passed to the
    // commands, without any calls made to it.
    google::cloud::bigtable::Table unused(
        google::cloud::bigtable::CreateDefaultDataClient(
            "unused-project", "Unused-instance",
            google::cloud::bigtable::ClientOptions()),
        "Unused-table");
    for (auto&& kv : commands) {
      try {
        kv.second(unused, cq, {});
      } catch (Usage const& u) {
        command_usage += "    ";
        command_usage += u.msg;
        command_usage += "\n";
      }
    }
  }

  if (argc < 5) {
    PrintUsage(argv[0],
               "Missing command and/or project-id/ or instance-id or table-id");
    return 1;
  }

  std::vector<std::string> args;
  args.emplace_back(argv[0]);
  std::string const command_name = argv[1];
  std::string const project_id = argv[2];
  std::string const instance_id = argv[3];
  std::string const table_id = argv[4];
  std::transform(argv + 4, argv + argc, std::back_inserter(args),
                 [](char* x) { return std::string(x); });

  auto command = commands.find(command_name);
  if (commands.end() == command) {
    PrintUsage(argv[0], "Unknown command: " + command_name);
    return 1;
  }

  // Start a thread to run the completion queue event loop.
  std::thread runner([&cq] { cq.Run(); });

  // Connect to the Cloud Bigtable endpoint.
  //! [connect data]
  google::cloud::bigtable::Table table(
      google::cloud::bigtable::CreateDefaultDataClient(
          project_id, instance_id, google::cloud::bigtable::ClientOptions()),
      table_id);
  //! [connect data]

  command->second(table, cq, args);

  // Shutdown the completion queue event loop and join the thread.
  cq.Shutdown();
  runner.join();

  return 0;
} catch (Usage const& ex) {
  PrintUsage(argv[0], ex.msg);
  return 1;
} catch (std::exception const& ex) {
  std::cerr << "Standard C++ exception raised: " << ex.what() << "\n";
  return 1;
}
//! [all code]
