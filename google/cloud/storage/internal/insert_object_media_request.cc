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

#include "google/cloud/storage/internal/insert_object_media_request.h"
#include "google/cloud/storage/internal/binary_data_as_debug_string.h"

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
std::ostream& operator<<(std::ostream& os, InsertObjectMediaRequest const& r) {
  os << "InsertObjectMediaRequest={bucket_name=" << r.bucket_name()
     << ", object_name=" << r.object_name();
  r.DumpParameters(os, ", ");
  os << ", contents=\n"
     << BinaryDataAsDebugString(r.contents().data(), r.contents().size());
  return os << "}";
}
}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
