// Copyright 2017 Google Inc.
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

#include "bigtable/client/data_client.h"
#include "bigtable/client/table.h"

#include <sstream>

#include <google/protobuf/text_format.h>

#include "bigtable/admin/admin_client.h"
#include "bigtable/admin/table_admin.h"

int main(int argc, char* argv[]) try {
  namespace admin_proto = ::google::bigtable::admin::v2;

  // Make sure the arguments are valid.
  if (argc != 4) {
    std::string const cmd = argv[0];
    auto last_slash = std::string(argv[0]).find_last_of("/");
    std::cerr << "Usage: " << cmd.substr(last_slash + 1)
              << " <project> <instance> <table>" << std::endl;
    return 1;
  }
  std::string const project_id = argv[1];
  std::string const instance_id = argv[2];
  std::string const table_name = argv[3];
  std::string const family = "fam";

  auto admin_client =
      bigtable::CreateAdminClient(project_id, bigtable::ClientOptions());
  bigtable::TableAdmin admin(admin_client, instance_id);

  auto created_table = admin.CreateTable(
      table_name, bigtable::TableConfig(
                      {{family, bigtable::GcRule::MaxNumVersions(1)}}, {}));
  std::cout << table_name << " created successfully" << std::endl;

  auto client = bigtable::CreateDefaultClient(project_id, instance_id,
                                              bigtable::ClientOptions());
  bigtable::Table table(client, table_name);

  // TODO(#29) - read the rows back when ReadRows() is implemented.
  bigtable::BulkMutation bulk{
      bigtable::SingleRowMutation("row-key-0",
                                  {bigtable::SetCell(family, "c0", 0, "v0"),
                                   bigtable::SetCell(family, "c1", 0, "v1")}),
      bigtable::SingleRowMutation("row-key-1",
                                  {bigtable::SetCell(family, "c0", 0, "v2"),
                                   bigtable::SetCell(family, "c1", 0, "v3")}),
  };
  table.BulkApply(std::move(bulk));
  std::cout << "bulk mutation successful" << std::endl;

  return 0;
} catch (bigtable::PermanentMutationFailure const& ex) {
  std::cerr << "bigtable::PermanentMutationFailure raised: " << ex.what()
            << " - " << ex.status().error_message() << " ["
            << ex.status().error_code()
            << "], details=" << ex.status().error_details() << std::endl;
  return 1;
} catch (std::exception const& ex) {
  std::cerr << "Standard exception raised: " << ex.what() << std::endl;
  return 1;
}
