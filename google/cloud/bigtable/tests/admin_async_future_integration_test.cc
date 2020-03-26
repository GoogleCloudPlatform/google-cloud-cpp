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

#include "google/cloud/bigtable/instance_admin.h"
#include "google/cloud/bigtable/testing/table_integration_test.h"
#include "google/cloud/internal/getenv.h"
#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/testing_util/chrono_literals.h"
#include "google/cloud/testing_util/init_google_mock.h"
#include <google/protobuf/util/time_util.h>
#include <gmock/gmock.h>

namespace google {
namespace cloud {
namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
namespace {
namespace btadmin = google::bigtable::admin::v2;
using namespace google::cloud::testing_util::chrono_literals;

class AdminAsyncFutureIntegrationTest
    : public bigtable::testing::TableIntegrationTest {
 protected:
  std::shared_ptr<AdminClient> admin_client_;
  std::unique_ptr<TableAdmin> table_admin_;
  std::unique_ptr<bigtable::InstanceAdmin> instance_admin_;

  void SetUp() {
    if (google::cloud::internal::GetEnv(
            "ENABLE_BIGTABLE_ADMIN_INTEGRATION_TESTS")
            .value_or("") != "yes") {
      GTEST_SKIP();
    }
    TableIntegrationTest::SetUp();
    admin_client_ = CreateDefaultAdminClient(
        testing::TableTestEnvironment::project_id(), ClientOptions());
    table_admin_ = google::cloud::internal::make_unique<TableAdmin>(
        admin_client_, bigtable::testing::TableTestEnvironment::instance_id());
    auto instance_admin_client = bigtable::CreateDefaultInstanceAdminClient(
        bigtable::testing::TableTestEnvironment::project_id(),
        bigtable::ClientOptions());
    instance_admin_ =
        google::cloud::internal::make_unique<bigtable::InstanceAdmin>(
            instance_admin_client);
  }

  void TearDown() {}

  int CountMatchingTables(std::string const& table_id,
                          std::vector<btadmin::Table> const& tables) {
    std::string table_name =
        table_admin_->instance_name() + "/tables/" + table_id;
    auto count = std::count_if(tables.begin(), tables.end(),
                               [&table_name](btadmin::Table const& t) {
                                 return table_name == t.name();
                               });
    return static_cast<int>(count);
  }

  int CountMatchingBackups(std::string const& cluster_id,
                           std::string const& backup_id,
                           std::vector<btadmin::Backup> const& backups) {
    std::string backup_name = table_admin_->instance_name() + "/clusters/" +
                              cluster_id + "/backups/" + backup_id;
    auto count = std::count_if(backups.begin(), backups.end(),
                               [&backup_name](btadmin::Backup const& t) {
                                 return backup_name == t.name();
                               });
    return static_cast<int>(count);
  }
};

/// @test Verify that `bigtable::TableAdmin` Async CRUD operations work as
/// expected.
TEST_F(AdminAsyncFutureIntegrationTest, CreateListGetDeleteTableTest) {
  // Currently this test uses mostly synchronous operations, as we implement
  // async versions we should replace them in this function.

  std::string const table_id = RandomTableId();

  CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  // AsyncCreateTable()
  TableConfig table_config({{"fam", GcRule::MaxNumVersions(5)},
                            {"foo", GcRule::MaxAge(std::chrono::hours(24))}},
                           {"a1000", "a2000", "b3000", "m5000"});

  auto count_matching_families = [](btadmin::Table const& table,
                                    std::string const& name) {
    int count = 0;
    for (auto const& kv : table.column_families()) {
      if (kv.first == name) {
        ++count;
      }
    }
    return count;
  };

  future<void> chain =
      table_admin_->AsyncListTables(cq, btadmin::Table::NAME_ONLY)
          .then([&](future<StatusOr<std::vector<btadmin::Table>>> fut) {
            StatusOr<std::vector<btadmin::Table>> result = fut.get();
            EXPECT_STATUS_OK(result);
            auto previous_count = CountMatchingTables(table_id, *result);
            EXPECT_EQ(0, previous_count)
                << "Table (" << table_id << ") already exists."
                << " This is unexpected, as the table ids are"
                << " generated at random.";
            return table_admin_->AsyncCreateTable(cq, table_id, table_config);
          })
          .then([&](future<StatusOr<btadmin::Table>> fut) {
            StatusOr<btadmin::Table> result = fut.get();
            EXPECT_STATUS_OK(result);
            EXPECT_THAT(result->name(), ::testing::HasSubstr(table_id));
            return table_admin_->AsyncGetTable(cq, table_id,
                                               btadmin::Table::FULL);
          })
          .then([&](future<StatusOr<btadmin::Table>> fut) {
            StatusOr<btadmin::Table> get_result = fut.get();
            EXPECT_STATUS_OK(get_result);

            EXPECT_EQ(1, count_matching_families(*get_result, "fam"));
            EXPECT_EQ(1, count_matching_families(*get_result, "foo"));

            // update table
            std::vector<bigtable::ColumnFamilyModification>
                column_modification_list = {
                    bigtable::ColumnFamilyModification::Create(
                        "newfam",
                        GcRule::Intersection(
                            GcRule::MaxAge(std::chrono::hours(7 * 24)),
                            GcRule::MaxNumVersions(1))),
                    bigtable::ColumnFamilyModification::Update(
                        "fam", GcRule::MaxNumVersions(2)),
                    bigtable::ColumnFamilyModification::Drop("foo")};
            return table_admin_->AsyncModifyColumnFamilies(
                cq, table_id, column_modification_list);
          })
          .then([&](future<StatusOr<btadmin::Table>> fut) {
            StatusOr<btadmin::Table> get_result = fut.get();
            EXPECT_EQ(1, count_matching_families(*get_result, "fam"));
            EXPECT_EQ(0, count_matching_families(*get_result, "foo"));
            EXPECT_EQ(1, count_matching_families(*get_result, "newfam"));
            auto const& gc =
                get_result->column_families().at("newfam").gc_rule();
            EXPECT_TRUE(gc.has_intersection());
            EXPECT_EQ(2, gc.intersection().rules_size());

            return table_admin_->AsyncDeleteTable(cq, table_id);
          })
          .then([&](future<Status> fut) {
            Status delete_result = fut.get();
            EXPECT_STATUS_OK(delete_result);
            return table_admin_->AsyncListTables(cq, btadmin::Table::NAME_ONLY);
          })
          .then([&](future<StatusOr<std::vector<btadmin::Table>>> fut) {
            StatusOr<std::vector<btadmin::Table>> result = fut.get();
            EXPECT_STATUS_OK(result);
            auto previous_count = CountMatchingTables(table_id, *result);
            ASSERT_EQ(0, previous_count)
                << "Table (" << table_id << ") already exists."
                << " This is unexpected, as the table ids are"
                << " generated at random.";
          });

  chain.get();
  SUCCEED();  // we expect that previous operations do not fail.

  cq.Shutdown();
  pool.join();
}

/// @test Verify that `bigtable::TableAdmin` AsyncDropRowsByPrefix works
TEST_F(AdminAsyncFutureIntegrationTest, AsyncDropRowsByPrefixTest) {
  auto table = GetTable();

  CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  // Create a vector of cell which will be inserted into bigtable
  std::string const row_key1_prefix = "DropRowPrefix1";
  std::string const row_key2_prefix = "DropRowPrefix2";
  std::string const row_key1 = row_key1_prefix + "-Key1";
  std::string const row_key1_1 = row_key1_prefix + "_1-Key1";
  std::string const row_key2 = row_key2_prefix + "-Key2";
  std::vector<bigtable::Cell> created_cells{
      {row_key1, "family1", "column_id1", 0, "v-c-0-0"},
      {row_key1, "family1", "column_id1", 1000, "v-c-0-1"},
      {row_key1, "family2", "column_id3", 2000, "v-c-0-2"},
      {row_key1_1, "family2", "column_id3", 2000, "v-c-0-2"},
      {row_key1_1, "family2", "column_id3", 3000, "v-c-0-2"},
      {row_key2, "family2", "column_id2", 2000, "v-c0-0-0"},
      {row_key2, "family3", "column_id3", 3000, "v-c1-0-2"},
  };
  std::vector<bigtable::Cell> expected_cells{
      {row_key2, "family2", "column_id2", 2000, "v-c0-0-0"},
      {row_key2, "family3", "column_id3", 3000, "v-c1-0-2"}};

  CreateCells(table, created_cells);

  future<void> chain =
      table_admin_
          ->AsyncDropRowsByPrefix(
              cq, bigtable::testing::TableTestEnvironment::table_id(),
              row_key1_prefix)
          .then([&](future<Status> fut) {
            Status delete_result = fut.get();
            EXPECT_STATUS_OK(delete_result);
            auto actual_cells =
                ReadRows(table, bigtable::Filter::PassAllFilter());
            CheckEqualUnordered(expected_cells, actual_cells);
          });

  chain.get();
  SUCCEED();
  cq.Shutdown();
  pool.join();
}

/// @test Verify that `bigtable::TableAdmin` AsyncDropAllRows works
TEST_F(AdminAsyncFutureIntegrationTest, AsyncDropAllRowsTest) {
  auto table = GetTable();

  CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  // Create a vector of cell which will be inserted into bigtable
  std::string const row_key1 = "DropRowKey1";
  std::string const row_key2 = "DropRowKey2";
  std::vector<bigtable::Cell> created_cells{
      {row_key1, "family1", "column_id1", 0, "v-c-0-0"},
      {row_key1, "family1", "column_id1", 1000, "v-c-0-1"},
      {row_key1, "family2", "column_id3", 2000, "v-c-0-2"},
      {row_key2, "family2", "column_id2", 2000, "v-c0-0-0"},
      {row_key2, "family3", "column_id3", 3000, "v-c1-0-2"},
  };

  CreateCells(table, created_cells);

  future<void> chain =
      table_admin_
          ->AsyncDropAllRows(
              cq, bigtable::testing::TableTestEnvironment::table_id())
          .then([&](future<Status> fut) {
            Status delete_result = fut.get();
            EXPECT_STATUS_OK(delete_result);
            auto actual_cells =
                ReadRows(table, bigtable::Filter::PassAllFilter());
            ASSERT_TRUE(actual_cells.empty());
          });

  chain.get();
  SUCCEED();
  cq.Shutdown();
  pool.join();
}

/// @test Verify that `bigtable::TableAdmin` AsyncCheckConsistency works as
/// expected.
TEST_F(AdminAsyncFutureIntegrationTest, AsyncCheckConsistencyIntegrationTest) {
  using namespace google::cloud::testing_util::chrono_literals;

  std::string id = bigtable::testing::TableTestEnvironment::RandomInstanceId();
  std::string const table_id = RandomTableId();

  auto project_id = bigtable::testing::TableTestEnvironment::project_id();

  auto instance_admin_client = bigtable::CreateDefaultInstanceAdminClient(
      project_id, bigtable::ClientOptions());
  bigtable::InstanceAdmin instance_admin(instance_admin_client);

  // need to create table_admin for dynamically created instance
  auto admin_client =
      bigtable::CreateDefaultAdminClient(project_id, bigtable::ClientOptions());
  bigtable::TableAdmin table_admin(admin_client, id);

  auto data_client = bigtable::CreateDefaultDataClient(
      project_id, id, bigtable::ClientOptions());
  bigtable::Table table(data_client, table_id);

  // Abbreviate "Integration Test" as "IT" because the display name cannot be
  // longer than 30 characters.
  auto display_name = ("IT " + id).substr(0, 30);

  // Replication needs at least two clusters
  auto cluster_config_1 =
      bigtable::ClusterConfig(bigtable::testing::TableTestEnvironment::zone_a(),
                              3, bigtable::ClusterConfig::HDD);
  auto cluster_config_2 =
      bigtable::ClusterConfig(bigtable::testing::TableTestEnvironment::zone_b(),
                              3, bigtable::ClusterConfig::HDD);
  bigtable::InstanceConfig config(
      id, display_name,
      {{id + "-c1", cluster_config_1}, {id + "-c2", cluster_config_2}});

  std::string const column_family1 = "family1";
  std::string const column_family2 = "family2";
  std::string const column_family3 = "family3";
  bigtable::TableConfig table_config = bigtable::TableConfig(
      {{column_family1, bigtable::GcRule::MaxNumVersions(10)},
       {column_family2, bigtable::GcRule::MaxNumVersions(10)},
       {column_family3, bigtable::GcRule::MaxNumVersions(10)}},
      {});

  // Create a vector of cell which will be inserted into bigtable
  std::string const row_key1 = "DropRowKey1";
  std::string const row_key2 = "DropRowKey2";
  std::vector<bigtable::Cell> created_cells{
      {row_key1, column_family1, "column_id1", 1000, "v-c-0-0"},
      {row_key1, column_family1, "column_id2", 1000, "v-c-0-1"},
      {row_key1, column_family2, "column_id3", 2000, "v-c-0-2"},
      {row_key2, column_family2, "column_id2", 2000, "v-c0-0-0"},
      {row_key2, column_family3, "column_id3", 3000, "v-c1-0-2"},
  };

  CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  future<Status> chain =
      instance_admin.AsyncCreateInstance(cq, config)
          .then([&](future<StatusOr<btadmin::Instance>> fut) {
            StatusOr<btadmin::Instance> result = fut.get();
            EXPECT_STATUS_OK(result);
            if (!result) {
              return make_ready_future(
                  StatusOr<btadmin::Table>(result.status()));
            }
            return table_admin.AsyncCreateTable(cq, table_id, table_config);
          })
          .then([&](future<StatusOr<btadmin::Table>> fut) {
            StatusOr<btadmin::Table> result = fut.get();
            EXPECT_STATUS_OK(result);
            if (!result) {
              return make_ready_future(StatusOr<std::string>(result.status()));
            }
            EXPECT_THAT(result->name(), ::testing::HasSubstr(table_id));
            CreateCells(table, created_cells);
            return table_admin.AsyncGenerateConsistencyToken(cq, table_id);
          })
          .then([&](future<StatusOr<std::string>> fut) {
            auto token = fut.get();
            EXPECT_STATUS_OK(token);
            if (!token) {
              return make_ready_future(StatusOr<Consistency>(token.status()));
            }
            return table_admin.AsyncWaitForConsistency(cq, table_id, *token);
          })
          .then([&](future<StatusOr<Consistency>> fut) {
            auto result = fut.get();
            EXPECT_STATUS_OK(result);
            if (!result) {
              return google::cloud::make_ready_future(result.status());
            }
            // If there is an error we cannot check the result, but
            // we want to delete the table and continue.
            EXPECT_EQ(*result, Consistency::kConsistent);
            return table_admin.AsyncDeleteTable(cq, table_id);
          })
          .then([&](future<Status> fut) {
            Status delete_result = fut.get();
            EXPECT_STATUS_OK(delete_result);
            return instance_admin.AsyncDeleteInstance(id, cq);
          });

  auto status = chain.get();
  EXPECT_STATUS_OK(status);
  cq.Shutdown();
  pool.join();
}
#if 0
/// @test Verify that `bigtable::TableAdmin` Backup Async CRUD operations work
/// as expected.
TEST_F(AdminAsyncFutureIntegrationTest, CreateListGetUpdateDeleteBackup) {
  std::string const table_id = RandomTableId();
  CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  // verify new table id in current table list
  auto previous_table_list =
      table_admin_->ListTables(btadmin::Table::NAME_ONLY);
  ASSERT_STATUS_OK(previous_table_list);
  auto previous_count = CountMatchingTables(table_id, *previous_table_list);
  ASSERT_EQ(0, previous_count) << "Table (" << table_id << ") already exists."
                               << " This is unexpected, as the table ids are"
                               << " generated at random.";

  TableConfig table_config({{"fam", GcRule::MaxNumVersions(5)},
                            {"foo", GcRule::MaxAge(std::chrono::hours(24))}},
                           {"a1000", "a2000", "b3000", "m5000"});
  // create table
  ASSERT_STATUS_OK(table_admin_->CreateTable(table_id, table_config));


  auto clusters_list =
      instance_admin_->ListClusters(table_admin_->instance_id());
  ASSERT_STATUS_OK(clusters_list);
  std::string const backup_cluster_full_name =
      clusters_list->clusters.begin()->name();
  std::string const backup_cluster_id = backup_cluster_full_name.substr(
      backup_cluster_full_name.rfind("/") + 1,
      backup_cluster_full_name.size() - backup_cluster_full_name.rfind("/"));
  std::string const backup_id = RandomBackupId();
  std::string const backup_full_name = backup_cluster_full_name + "/backups/" +
          backup_id;
  google::protobuf::Timestamp const expire_time =
      google::protobuf::util::TimeUtil::GetCurrentTime() +
      google::protobuf::util::TimeUtil::HoursToDuration(12);
  google::protobuf::Timestamp const updated_expire_time =
      expire_time + google::protobuf::util::TimeUtil::HoursToDuration(12);

  future<void> chain =
      table_admin_->AsyncListBackups(cq, {})
          .then([&](future<StatusOr<std::vector<btadmin::Backup>>> fut) {
            StatusOr<std::vector<btadmin::Backup>> result = fut.get();
            EXPECT_STATUS_OK(result);
            auto previous_count =
                CountMatchingBackups(backup_cluster_id, backup_id, *result);
            EXPECT_EQ(0, previous_count)
                << "Backup (" << backup_id << ") already exists."
                << " This is unexpected, as the backup ids are"
                << " generated at random.";
            return table_admin_->AsyncCreateBackup(
                cq, {backup_cluster_id, backup_id, table_id, expire_time});
          })
          .then([&](future<StatusOr<btadmin::Backup>> fut) {
            StatusOr<btadmin::Backup> result = fut.get();
            EXPECT_STATUS_OK(result);
            EXPECT_THAT(result->name(), ::testing::HasSubstr(backup_id));
            return table_admin_->AsyncGetBackup(cq, backup_cluster_id,
                                                backup_id);
          })
          .then([&](future<StatusOr<btadmin::Backup>> fut) {
            StatusOr<btadmin::Backup> get_result = fut.get();
            EXPECT_STATUS_OK(get_result);
            EXPECT_EQ(get_result->name(), backup_full_name);
            return table_admin_->AsyncUpdateBackup(
                cq, {backup_cluster_id, backup_id, updated_expire_time});
          })
          .then([&](future<StatusOr<btadmin::Backup>> fut) {
            StatusOr<btadmin::Backup> update_result = fut.get();
            EXPECT_STATUS_OK(update_result);
            EXPECT_EQ(update_result->name(), backup_full_name);
            EXPECT_EQ(update_result->expire_time(), updated_expire_time);
            return table_admin_->AsyncDeleteBackup(cq, backup_cluster_id,
                                                   backup_id);
          })
          .then([&](future<Status> fut) {
            Status delete_result = fut.get();
            EXPECT_STATUS_OK(delete_result);
            return table_admin_->AsyncListBackups(cq, {});
          })
          .then([&](future<StatusOr<std::vector<btadmin::Backup>>> fut) {
            StatusOr<std::vector<btadmin::Backup>> result = fut.get();
            EXPECT_STATUS_OK(result);
            auto previous_count =
                CountMatchingBackups(backup_cluster_id, backup_id, *result);
            ASSERT_EQ(0, previous_count)
                << "Backup (" << backup_id << ") still exists.";
          });
  chain.get();

  // delete table
  EXPECT_STATUS_OK(table_admin_->DeleteTable(table_id));
  // List to verify it is no longer there
  auto current_table_list = table_admin_->ListTables(btadmin::Table::NAME_ONLY);
  ASSERT_STATUS_OK(current_table_list);
  auto table_count = CountMatchingTables(table_id, *current_table_list);
  EXPECT_EQ(0, table_count);

  SUCCEED();  // we expect that previous operations do not fail.

  cq.Shutdown();
  pool.join();
}

/// @test Verify that `bigtable::TableAdmin` Async Backup and Restore
/// operations work as expected.
TEST_F(AdminAsyncFutureIntegrationTest, RestoreTableFromBackup) {
  std::string const table_id = RandomTableId();
  CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  // verify new table id does not exist
  auto previous_table_list =
      table_admin_->ListTables(btadmin::Table::NAME_ONLY);
  ASSERT_STATUS_OK(previous_table_list);
  auto previous_count = CountMatchingTables(table_id, *previous_table_list);
  ASSERT_EQ(0, previous_count) << "Table (" << table_id << ") already exists."
                               << " This is unexpected, as the table ids are"
                               << " generated at random.";

  TableConfig table_config({{"fam", GcRule::MaxNumVersions(5)},
                            {"foo", GcRule::MaxAge(std::chrono::hours(24))}},
                           {"a1000", "a2000", "b3000", "m5000"});
  // create table
  ASSERT_STATUS_OK(table_admin_->CreateTable(table_id, table_config));

  auto clusters_list =
      instance_admin_->ListClusters(table_admin_->instance_id());
  ASSERT_STATUS_OK(clusters_list);
  std::string const backup_cluster_full_name =
      clusters_list->clusters.begin()->name();
  std::string const backup_cluster_id = backup_cluster_full_name.substr(
      backup_cluster_full_name.rfind("/") + 1,
      backup_cluster_full_name.size() - backup_cluster_full_name.rfind("/"));
  std::string const backup_id = RandomBackupId();
  std::string const backup_full_name = backup_cluster_full_name + "/backups/" +
          backup_id;
  google::protobuf::Timestamp const expire_time =
      google::protobuf::util::TimeUtil::GetCurrentTime() +
      google::protobuf::util::TimeUtil::HoursToDuration(12);

  future<void> chain =
      table_admin_->AsyncListBackups(cq, {})
          .then([&](future<StatusOr<std::vector<btadmin::Backup>>> fut) {
            StatusOr<std::vector<btadmin::Backup>> result = fut.get();
            EXPECT_STATUS_OK(result);
            auto previous_count =
                CountMatchingBackups(backup_cluster_id, backup_id, *result);
            EXPECT_EQ(0, previous_count)
                << "Backup (" << backup_id << ") already exists."
                << " This is unexpected, as the backup ids are"
                << " generated at random.";
            return table_admin_->AsyncCreateBackup(
                cq, {backup_cluster_id, backup_id, table_id, expire_time});
          })
          .then([&](future<StatusOr<btadmin::Backup>> fut) {
            StatusOr<btadmin::Backup> result = fut.get();
            EXPECT_STATUS_OK(result);
            EXPECT_THAT(result->name(), ::testing::HasSubstr(backup_id));
            return table_admin_->AsyncDeleteTable(cq, table_id);
          })
          .then([&](future<Status> fut) {
            Status delete_table_result = fut.get();
            EXPECT_STATUS_OK(delete_table_result);
            return table_admin_->AsyncRestoreTable(
                cq, {table_id, backup_cluster_id, backup_id});
          })
          .then([&](future<StatusOr<btadmin::Table>> fut) {
            auto restore_result = fut.get();
            EXPECT_STATUS_OK(restore_result);
          });
  chain.get();

  // verify table was restored
  auto current_table_list = table_admin_->ListTables(btadmin::Table::NAME_ONLY);
  ASSERT_STATUS_OK(current_table_list);
  auto table_count = CountMatchingTables(table_id, *current_table_list);
  EXPECT_EQ(1, table_count);

  // delete backup
  EXPECT_STATUS_OK(table_admin_->DeleteBackup(backup_cluster_id, backup_id));
  // delete table
  EXPECT_STATUS_OK(table_admin_->DeleteTable(table_id));

  SUCCEED();  // we expect that previous operations do not fail.

  cq.Shutdown();
  pool.join();
}
#endif
}  // namespace
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google

int main(int argc, char* argv[]) {
  google::cloud::testing_util::InitGoogleMock(argc, argv);
  (void)::testing::AddGlobalTestEnvironment(
      new google::cloud::bigtable::testing::TableTestEnvironment);
  return RUN_ALL_TESTS();
}
