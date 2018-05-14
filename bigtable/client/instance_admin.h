// Copyright 2018 Google Inc.
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

#ifndef GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_INSTANCE_ADMIN_H_
#define GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_INSTANCE_ADMIN_H_

#include "bigtable/client/bigtable_strong_types.h"
#include "bigtable/client/instance_admin_client.h"
#include "bigtable/client/instance_config.h"
#include "bigtable/client/internal/instance_admin.h"
#include <future>
#include <memory>

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Implements a minimal API to administer Cloud Bigtable instances.
 */
class InstanceAdmin {
 public:
  /**
   * @param client the interface to create grpc stubs, report errors, etc.
   */
  InstanceAdmin(std::shared_ptr<InstanceAdminClient> client)
      : impl_(std::move(client)) {}

  /**
   * Create a new InstanceAdmin using explicit policies to handle RPC errors.
   *
   * @tparam RPCRetryPolicy control which operations to retry and for how long.
   * @tparam RPCBackoffPolicy control how does the client backs off after an RPC
   *     error.
   * @param client the interface to create grpc stubs, report errors, etc.
   * @param retry_policy the policy to handle RPC errors.
   * @param backoff_policy the policy to control backoff after an error.
   */
  template <typename RPCRetryPolicy, typename RPCBackoffPolicy>
  InstanceAdmin(std::shared_ptr<InstanceAdminClient> client,
                RPCRetryPolicy retry_policy, RPCBackoffPolicy backoff_policy)
      : impl_(std::move(client), std::move(retry_policy),
              std::move(backoff_policy)) {}

  /// The full name (`projects/<project_id>`) of the project.
  std::string const& project_name() const { return impl_.project_name(); }
  /// The project id, i.e., `project_name()` without the `projects/` prefix.
  std::string const& project_id() const { return impl_.project_id(); }

  /// Return the fully qualified name of the given instance_id.
  std::string InstanceName(std::string const& instance_id) const {
    return impl_.InstanceName(instance_id);
  }

  /**
   * Create a new instance of Cloud Bigtable.
   *
   * @warning Note that this is operation can take seconds or minutes to
   * complete. The application may prefer to perform other work while waiting
   * for this operation.
   *
   * @param instance_config a description of the new instance to be created.
   * @return a future that becomes satisfied when (a) the operation has
   *   completed successfully, in which case it returns a proto with the
   *   Instance details, (b) the operation has failed, in which case the future
   *   contains an exception (typically `bigtable::GrpcError`) with the details
   *   of the failure, or (c) the state of the operation is unknown after the
   *   time allocated by the retry policies has expired, in which case the
   *   future contains an exception of type `bigtable::PollTimeout`.
   *
   * @par Example
   * @snippet bigtable_samples_instance_admin.cc create instance
   */
  std::future<google::bigtable::admin::v2::Instance> CreateInstance(
      InstanceConfig instance_config);

  /// Create Cluster.
  /// TODO(#422) implement tests and examples for CreateCluster
  std::future<google::bigtable::admin::v2::Cluster> CreateCluster(
      ClusterConfig instance_config, std::string const& instance_id,
      std::string const& cluster_id);

  /**
   * Return the list of instances in the project.
   *
   * @par Example
   * @snippet bigtable_samples_instance_admin.cc list instances
   */
  std::vector<google::bigtable::admin::v2::Instance> ListInstances();

  /**
   * Return the details of @p instance_id.
   *
   * @par Example
   * @snippet bigtable_samples_instance_admin.cc get instance
   */
  google::bigtable::admin::v2::Instance GetInstance(
      std::string const& instance_id);

  /**
   * Deletes the instances in the project.
   * @param instance_id the id of the instance in the project that needs to be
   * deleted
   *
   * @par Example
   * @snippet bigtable_samples_instance_admin.cc delete instance
   */
  void DeleteInstance(std::string const& instance_id);

  /**
   * Return the list of clusters in an instance.
   *
   * @par Example
   * @snippet bigtable_samples_instance_admin.cc list clusters
   */
  std::vector<google::bigtable::admin::v2::Cluster> ListClusters();

  /**
   * Return the list of clusters in an instance.
   *
   * @par Example
   * @snippet bigtable_samples_instance_admin.cc list clusters
   */
  std::vector<google::bigtable::admin::v2::Cluster> ListClusters(
      std::string const& instance_id);

  /**
   * Deletes the specified cluster of an instance in the project.
   *
   * @param instance_id the id of the instance in the project
   * @param cluster_id the id of the cluster in the project that needs to be
   *   deleted
   *
   *  @par Example
   *  @snippet bigtable_samples_instance_admin.cc delete cluster
   */
  void DeleteCluster(bigtable::InstanceId const& instance_id,
                     bigtable::ClusterId const& cluster_id);

 private:
  /// Implement CreateInstance() with a separate thread.
  google::bigtable::admin::v2::Instance CreateInstanceImpl(
      InstanceConfig instance_config);

  /// Implement CreateCluster() with a separate thread.
  google::bigtable::admin::v2::Cluster CreateClusterImpl(
      ClusterConfig instance_config, std::string const& instance_id,
      std::string const& cluster_id);

 private:
  noex::InstanceAdmin impl_;
};

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_INSTANCE_ADMIN_H_
