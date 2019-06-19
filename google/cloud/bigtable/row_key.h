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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_ROW_KEY_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_ROW_KEY_H_

#include "google/cloud/bigtable/version.h"
#include <google/bigtable/v2/data.pb.h>
#include <type_traits>
#include <utility>

namespace google {
namespace cloud {
namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
/**
 * Defines the type for row keys.
 *
 * Inside Google row keys are not represented by `std::string`. To minimize
 * friction during imports we define the type using a `decltype()` expression.
 *
 * Users of the Cloud Bigtable C++ client library should treat this as a
 * complicated `typedef` for `std::string`. We have no plans to change the type
 * in the external version of the C++ client library in the foreseeable future.
 * If we ever did we would treat such a change as a reason to update the library
 * major version number, and we would give users time to migrate.
 *
 * In other words, external users of the Cloud Bigtable C++ client should simply
 * write `std::string` where this type appears. For Google projects that must
 * compile both inside and outside Google, this alias may be convenient.
 */
using RowKeyType = std::decay<decltype(
    std::declval<google::bigtable::v2::Row>().key())>::type;

namespace internal {
inline bool IsEmptyRowKey(RowKeyType const& key) {
  return key.empty();
}

inline bool IsEmptyRowKey(char const* key) {
  return std::string{} == key;
}

#if __cplusplus >= 201703L
inline bool IsEmptyRowKey(std::string_view const& key) {
  return key.empty();
}
#endif  // __cplusplus

inline int CompareRowKey(RowKeyType const& lhs, RowKeyType const& rhs) {
  return lhs.compare(rhs);
}
}  // namespace internal
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_ROW_KEY_H_
