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

#include "google/cloud/bigtable/grpc_error.h"
#include "google/cloud/bigtable/instance_admin.h"
#include "google/cloud/testing_util/init_google_mock.h"
#include <gmock/gmock.h>

namespace btadmin = google::bigtable::admin::v2;
namespace bigtable = google::cloud::bigtable;

namespace {
class InstanceTestEnvironment : public ::testing::Environment {
 public:
  explicit InstanceTestEnvironment(std::string project, std::string zone,
                                   std::string replication_zone) {
    project_id_ = std::move(project);
    zone_ = std::move(zone);
    replication_zone_ = std::move(replication_zone);
  }

  static std::string const& project_id() { return project_id_; }
  static std::string const& zone() { return zone_; }
  static std::string const& replication_zone() { return replication_zone_; }

 private:
  static std::string project_id_;
  static std::string zone_;
  static std::string replication_zone_;
};

std::string InstanceTestEnvironment::project_id_;
std::string InstanceTestEnvironment::zone_;
std::string InstanceTestEnvironment::replication_zone_;

class InstanceAdminAsyncIntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    instance_admin_client_ = bigtable::CreateDefaultInstanceAdminClient(
        InstanceTestEnvironment::project_id(), bigtable::ClientOptions());
    instance_admin_ =
        google::cloud::internal::make_unique<bigtable::InstanceAdmin>(
            instance_admin_client_);
  }

 protected:
  std::unique_ptr<bigtable::InstanceAdmin> instance_admin_;
  std::shared_ptr<bigtable::InstanceAdminClient> instance_admin_client_;
  google::cloud::internal::DefaultPRNG generator_ =
      google::cloud::internal::MakeDefaultPRNG();
};

bool IsInstancePresent(std::vector<btadmin::Instance> const& instances,
                       std::string const& instance_name) {
  return instances.end() !=
         std::find_if(instances.begin(), instances.end(),
                      [&instance_name](btadmin::Instance const& i) {
                        return i.name() == instance_name;
                      });
}

bool IsClusterPresent(std::vector<btadmin::Cluster> const& clusters,
                      std::string const& cluster_name) {
  return clusters.end() !=
         std::find_if(clusters.begin(), clusters.end(),
                      [&cluster_name](btadmin::Cluster const& i) {
                        return i.name() == cluster_name;
                      });
}

bigtable::InstanceConfig IntegrationTestConfig(
    std::string const& id,
    std::string const& zone = InstanceTestEnvironment::zone(),
    bigtable::InstanceConfig::InstanceType instance_type =
        bigtable::InstanceConfig::DEVELOPMENT,
    int32_t serve_node = 0) {
  bigtable::InstanceId instance_id(id);
  bigtable::DisplayName display_name("Integration Tests " + id);
  auto cluster_config =
      bigtable::ClusterConfig(zone, serve_node, bigtable::ClusterConfig::HDD);
  bigtable::InstanceConfig config(instance_id, display_name,
                                  {{id + "-c1", cluster_config}});
  config.set_type(instance_type);
  return config;
}

}  // anonymous namespace

/// @test Verify that Instance async CRUD operations work as expected.
TEST_F(InstanceAdminAsyncIntegrationTest, AsyncCreateListDeleteInstanceTest) {
  std::string instance_id =
      "it-" + google::cloud::internal::Sample(
                  generator_, 8, "abcdefghijklmnopqrstuvwxyz0123456789");

  // verify new instance id in list of instances
  auto instances_before = instance_admin_->ListInstances();
  ASSERT_FALSE(IsInstancePresent(instances_before, instance_id))
      << "Instance (" << instance_id << ") already exists."
      << " This is unexpected, as the instance ids are"
      << " generated at random.";

  google::cloud::bigtable::CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  // create instance
  auto config = IntegrationTestConfig(instance_id);
  auto instance = instance_admin_->CreateInstance(config).get();
  auto instances_current = instance_admin_->ListInstances();
  EXPECT_TRUE(IsInstancePresent(instances_current, instance.name()));

  // Get instance
  bigtable::noex::InstanceAdmin admin(instance_admin_client_);
  std::promise<btadmin::Instance> done;
  admin.AsyncGetInstance(
      instance_id, cq,
      [&done](google::cloud::bigtable::CompletionQueue& cq,
              btadmin::Instance& instance, grpc::Status const& status) {
        done.set_value(std::move(instance));
      });
  auto instance_result = done.get_future().get();
  auto const npos = std::string::npos;
  EXPECT_NE(npos, instance_result.name().find(instance_admin_->project_name()));
  EXPECT_NE(npos, instance_result.name().find(instance_id));

  // Delete instance
  std::promise<google::protobuf::Empty> promise_delete_instance;
  admin.AsyncDeleteInstance(
      instance_id, cq,
      [&promise_delete_instance](google::cloud::bigtable::CompletionQueue& cq,
                                 google::protobuf::Empty& response,
                                 grpc::Status const& status) {
        promise_delete_instance.set_value(std::move(response));
      });
  auto response = promise_delete_instance.get_future().get();
  auto instances_after_delete = instance_admin_->ListInstances();
  EXPECT_TRUE(IsInstancePresent(instances_current, instance.name()));
  EXPECT_FALSE(IsInstancePresent(instances_after_delete, instance.name()));

  cq.Shutdown();
  pool.join();
}

/// @test Verify that cluster async CRUD operations work as expected.
TEST_F(InstanceAdminAsyncIntegrationTest, AsyncCreateListDeleteClusterTest) {
  std::string id =
      "it-" + google::cloud::internal::Sample(
                  generator_, 8, "abcdefghijklmnopqrstuvwxyz0123456789");
  std::string cluster_id_str = id + "-cl2";

  // create instance prerequisites for cluster operations
  bigtable::InstanceId instance_id(id);
  auto instance_config =
      IntegrationTestConfig(id, InstanceTestEnvironment::zone(),
                            bigtable::InstanceConfig::PRODUCTION, 3);
  auto instance_details =
      instance_admin_->CreateInstance(instance_config).get();

  google::cloud::bigtable::CompletionQueue cq;
  std::thread pool([&cq] { cq.Run(); });

  // create cluster
  auto clusters_before = instance_admin_->ListClusters(id);
  ASSERT_FALSE(IsClusterPresent(clusters_before, cluster_id_str))
      << "Cluster (" << cluster_id_str << ") already exists."
      << " This is unexpected, as the cluster ids are"
      << " generated at random.";
  bigtable::ClusterId cluster_id(cluster_id_str);
  auto cluster_config =
      bigtable::ClusterConfig(InstanceTestEnvironment::replication_zone(), 3,
                              bigtable::ClusterConfig::HDD);
  auto cluster =
      instance_admin_->CreateCluster(cluster_config, instance_id, cluster_id)
          .get();
  auto clusters_after = instance_admin_->ListClusters(id);
  EXPECT_FALSE(IsClusterPresent(clusters_before, cluster.name()));
  EXPECT_TRUE(IsClusterPresent(clusters_after, cluster.name()));

  // Get cluster
  bigtable::noex::InstanceAdmin admin(instance_admin_client_);
  std::promise<btadmin::Cluster> done;
  admin.AsyncGetCluster(
      instance_id, cluster_id, cq,
      [&done](google::cloud::bigtable::CompletionQueue& cq,
              btadmin::Cluster& cluster, grpc::Status const& status) {
        done.set_value(std::move(cluster));
      });
  auto cluster_result = done.get_future().get();
  std::string cluster_name_prefix =
      instance_admin_->project_name() + "/instances/" + id + "/clusters/";
  EXPECT_EQ(cluster_name_prefix + cluster_id.get(), cluster_result.name());

  // Delete cluster
  std::promise<google::protobuf::Empty> promise_delete_cluster;
  admin.AsyncDeleteCluster(
      instance_id, cluster_id, cq,
      [&promise_delete_cluster](google::cloud::bigtable::CompletionQueue& cq,
                                google::protobuf::Empty& response,
                                grpc::Status const& status) {
        promise_delete_cluster.set_value(std::move(response));
      });
  auto response = promise_delete_cluster.get_future().get();
  auto clusters_after_delete = instance_admin_->ListClusters(id);
  instance_admin_->DeleteInstance(id);
  EXPECT_TRUE(IsClusterPresent(
      clusters_after, instance_details.name() + "/clusters/" + id + "-cl2"));
  EXPECT_FALSE(
      IsClusterPresent(clusters_after_delete,
                       instance_details.name() + "/clusters/" + id + "-cl2"));

  cq.Shutdown();
  pool.join();
}

int main(int argc, char* argv[]) {
  google::cloud::testing_util::InitGoogleMock(argc, argv);

  if (argc != 4) {
    std::string const cmd = argv[0];
    auto last_slash = std::string(cmd).find_last_of('/');
    // Show usage if number of arguments is invalid.
    std::cerr << "Usage: " << cmd.substr(last_slash + 1)
              << "<project_id> <instance_id> <zone> <replication_zone>"
              << std::endl;
    return 1;
  }

  std::string const project_id = argv[1];
  std::string const zone = argv[2];
  std::string const replication_zone = argv[3];
  (void)::testing::AddGlobalTestEnvironment(
      new InstanceTestEnvironment(project_id, zone, replication_zone));

  return RUN_ALL_TESTS();
}
