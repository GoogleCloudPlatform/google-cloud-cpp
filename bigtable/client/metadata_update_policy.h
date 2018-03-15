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

#ifndef GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_METADATA_UPDATE_POLICY_H_
#define GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_METADATA_UPDATE_POLICY_H_

#include <bigtable/client/version.h>

#include <grpc++/grpc++.h>
#include <memory>

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Define the class for governing x-goog-request-params metadata value.
 * The value of x-goog-request-params starts with one of the following suffix
 *    "parent=" : Operation in instance, e.g. TableAdmin::CreateTable.
 *    "table_name=" : table_id is known at the time of creation, e.g.
 *     Table::Apply.
 *    "name=" : this is used when table|_id is known only in the RPC call, e.g.
 *     TableAdmin::GetTable.
 *
 */
class MetadataParamTypes final {
 public:
  static const MetadataParamTypes PARENT;
  static const MetadataParamTypes NAME;
  static const MetadataParamTypes TABLE_NAME;

  bool operator==(MetadataParamTypes const& that) const {
    return type_ == that.type_;
  }
  std::string getType() const { return std::move(type_); }

 private:
  std::string type_;
  MetadataParamTypes(std::string type) : type_(type) {}
};

/// MetadataUpdatePolicy holds supported metadata and setup ClientContext
class MetadataUpdatePolicy {
 public:
  /**
   * Constructor with default metadata pair.
   *
   * @param resource_name hierarchical name of resource, including  project id,
   * instance id
   *        and/or table_id.
   * @param metadata_param_type type to decide prefix for the value of
   *     x-goog-request-params
   */
  MetadataUpdatePolicy(std::string resource_name,
                       MetadataParamTypes metadata_param_type);

  /**
   * Constructor with default metadata pair.
   *
   * @param resource_name hierarchical name of resource, including  project id,
   * instance id
   *        and/or table_id.
   * @param metadata_param_type type to decide prefix for the value of
   *     x-goog-request-params.
   * @param table_id table_id used in RPC call.
   */
  MetadataUpdatePolicy(std::string resource_name,
                       MetadataParamTypes metadata_param_type,
                       std::string table_id);

  MetadataUpdatePolicy(MetadataUpdatePolicy const& policy);

  // Update the ClientContext for the next call.
  void setup(grpc::ClientContext& context) const;

  std::pair<std::string, std::string> get_google_cloud_resource_prefix() const {
    return google_cloud_resource_prefix_;
  }

  std::pair<std::string, std::string> get_x_google_request_params() const {
    return x_google_request_params_;
  }

 private:
  std::pair<std::string, std::string> google_cloud_resource_prefix_;
  std::pair<std::string, std::string> x_google_request_params_;
};

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_METADATA_UPDATE_POLICY_H_
