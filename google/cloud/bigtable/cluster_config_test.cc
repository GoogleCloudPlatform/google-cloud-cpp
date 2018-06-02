// Copyright 2018 Google LLC
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

#include "google/cloud/bigtable/cluster_config.h"
#include <gmock/gmock.h>

TEST(ClusterConfigTest, Constructor) {
  bigtable::ClusterConfig config("somewhere", 7, bigtable::ClusterConfig::SSD);
  auto proto = config.as_proto();
  EXPECT_EQ("somewhere", proto.location());
  EXPECT_EQ(7, proto.serve_nodes());
  EXPECT_EQ(bigtable::ClusterConfig::SSD, proto.default_storage_type());
}

TEST(ClusterConfigTest, Move) {
  bigtable::ClusterConfig config("somewhere", 7, bigtable::ClusterConfig::HDD);
  auto proto = config.as_proto_move();
  EXPECT_EQ("somewhere", proto.location());
  EXPECT_EQ(7, proto.serve_nodes());
  EXPECT_EQ(bigtable::ClusterConfig::HDD, proto.default_storage_type());
}
