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

#include <google/spanner/admin/database/v1/spanner_database_admin.grpc.pb.h>
#include <google/spanner/v1/spanner.grpc.pb.h>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>

namespace {

int ListDatabases(std::vector<std::string> args) {
  if (args.size() != 4U) {
    std::cerr << args[0] << ": list-databases <project> <instance>\n";
    return 1;
  }
  auto const& project = args[2];
  auto const& instance = args[3];

  namespace spanner = google::spanner::admin::database::v1;

  std::shared_ptr<grpc::ChannelCredentials> cred =
      grpc::GoogleDefaultCredentials();
  std::shared_ptr<grpc::Channel> channel =
      grpc::CreateChannel("spanner.googleapis.com", std::move(cred));
  std::unique_ptr<spanner::DatabaseAdmin::Stub> stub(
      spanner::DatabaseAdmin::NewStub(std::move(channel)));

  spanner::ListDatabasesResponse response;
  spanner::ListDatabasesRequest request;
  request.set_parent("projects/" + project + "/instances/" + instance);

  grpc::ClientContext context;
  grpc::Status status = stub->ListDatabases(&context, request, &response);

  if (!status.ok()) {
    std::cerr << "FAILED: " << status.error_code() << ": "
              << status.error_message() << "\n";
    return 1;
  }

  std::cout << "Response:\n";
  std::cout << response.DebugString() << "\n";
  return 0;
}

int PopulateTimeseriesTable(std::vector<std::string> args) {
  if (args.size() != 4U) {
    std::cerr << args[0] << ": populate-timeseries <project> <instance>"
              << " <database>\n";
    return 1;
  }
  auto const& project = args[2];
  auto const& instance = args[3];
  auto const& database = args[4];

  std::string database_name = "projects/" + project + "/instances/" +
      instance + "/databases/" + database;

  namespace spanner = google::spanner::v1;

  std::shared_ptr<grpc::ChannelCredentials> cred =
      grpc::GoogleDefaultCredentials();
  std::shared_ptr<grpc::Channel> channel =
      grpc::CreateChannel("spanner.googleapis.com", cred);
  auto  stub =
      spanner::Spanner::NewStub(std::move(channel));

  spanner::Session session = [&] {
    spanner::Session session;
    spanner::CreateSessionRequest request;
    request.set_database(database);

    grpc::ClientContext context;
    grpc::Status status = stub->CreateSession(&context, request, &session);
    if (!status.ok()) {
      std::cerr << "FAILED: [" << status.error_code() << "] - " << status
      .error_message() << "\n";
      std::exit(1);
    }
    return session;
  }();

  std::cout << "Session: " << session.name() << "\n";

  return 0;
}

}  // namespace

// This is a command-line tool to let folks easily experiment with Spanner
// using C++. This works with bazel using a command like:
//
// $ bazel run google/cloud/spanner:spanner_tool --
//       jgm-cloud-cxx jgm-spanner-instance
//
// Currently, the above command will just invoke the "ListDatabases" RPC, which
// makes it equivalent to the following command:
//
// $ gcloud spanner databases list
//       --project jgm-cloud-cxx --instance jgm-spanner-instance
//
// NOTE: The actual project and instance names will vary for other users; These
// are just examples.
int main(int argc, char* argv[]) {
  using CommandType = std::function<int(std::vector<std::string> args)>;

  std::map<std::string, CommandType> commands = {
      {"list-databases", &ListDatabases},
      {"populate-timeseries", &PopulateTimeseriesTable},
  };

  if (argc < 2) {
    std::cerr << argv[0] << ": missing command\n"
              << "Usage: " << argv[0] << " <command-name> [command-arguments]\n"
              << "Valid commands are:\n";
    for (auto const& kv : commands) {
      // Calling the command with an empty list always prints their usage.
      kv.second({});
    }
    return 1;
  }

  std::vector<std::string> args;
  std::transform(argv, argv + argc, std::back_inserter(args),
                 [](char* x) { return std::string(x); });

  std::string const command_name = args[1];
  auto command = commands.find(command_name);
  if (commands.end() == command) {
    std::cerr << argv[0] << ": unknown command " << command_name << '\n';
    for (auto const& kv : commands) {
      // Calling the command with an empty list always prints their usage.
      kv.second({});
    }
    return 1;
  }

  // Run the requested command.
  return command->second(args);
}
