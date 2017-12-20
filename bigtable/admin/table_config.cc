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

#include "bigtable/admin/table_config.h"

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
void TableConfig::MoveTo(
    ::google::bigtable::admin::v2::CreateTableRequest& request) {
  // As a challenge, we implement the strong exception guarantee in this
  // function.
  // First create a temporary value to hold intermediate computations.
  ::google::bigtable::admin::v2::CreateTableRequest tmp;
  auto& table = *tmp.mutable_table();
  // Make sure there are nodes to receive all the values in column_families_.
  auto& families = *table.mutable_column_families();
  for (auto const& kv : column_families_) {
    families[kv.first].mutable_gc_rule()->Clear();
  }
  // Make sure there is space to receive all the values in initial_splits_.
  tmp.mutable_initial_splits()->Reserve(initial_splits_.size());
  // Copy the granularity.
  table.set_granularity(timestamp_granularity());

  // None of the operations that follow can fail, they are all `noexcept`:
  for (auto& kv : column_families_) {
    *families[kv.first].mutable_gc_rule() = kv.second.as_proto_move();
  }
  for (auto& split : initial_splits_) {
    tmp.add_initial_splits()->set_key(std::move(split));
  }
  request.mutable_table()->Swap(tmp.mutable_table());
  request.mutable_initial_splits()->Swap(tmp.mutable_initial_splits());
  initial_splits_.clear();
  column_families_.clear();
  granularity_ = TIMESTAMP_GRANULARITY_UNSPECIFIED;
}

constexpr TableConfig::TimestampGranularity TableConfig::MILLIS;
constexpr TableConfig::TimestampGranularity
    TableConfig::TIMESTAMP_GRANULARITY_UNSPECIFIED;

}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
