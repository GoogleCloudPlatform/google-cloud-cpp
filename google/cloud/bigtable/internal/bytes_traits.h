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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_INTERNAL_BYTES_TRAITS_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_INTERNAL_BYTES_TRAITS_H_

#include "google/cloud/bigtable/internal/google_bytes_traits.h"
#include "google/cloud/bigtable/version.h"
#include "google/cloud/internal/big_endian.h"

namespace google {
namespace cloud {
namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
namespace internal {
inline bool IsEmptyRowKey(std::string const& key) { return key.empty(); }

inline bool IsEmptyRowKey(char const* key) { return std::string{} == key; }

inline int CompareRowKey(std::string const& lhs, std::string const& rhs) {
  return lhs.compare(rhs);
}

/// Returns true iff a < b and there is no string c such that a < c < b.
bool ConsecutiveRowKeys(std::string const& a, std::string const& b);

inline int CompareColumnQualifiers(std::string const& lhs,
                                   std::string const& rhs) {
  return lhs.compare(rhs);
}

template <typename T>
StatusOr<T> DecodeBigEndianCellValue(std::string const& c) {
  return google::cloud::internal::DecodeBigEndian<T>(std::string(c));
}

inline int CompareCellValues(std::string const& lhs, std::string const& rhs) {
  return lhs.compare(rhs);
}

inline void AppendCellValue(std::string& value, std::string const& fragment) {
  value.append(fragment);
}

inline void ReserveCellValue(std::string& value, std::size_t reserve) {
  value.reserve(reserve);
}

}  // namespace internal
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_INTERNAL_BYTES_TRAITS_H_
