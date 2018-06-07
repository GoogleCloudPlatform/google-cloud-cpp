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

#include "google/cloud/storage/internal/metadata_parser.h"
#include "google/cloud/internal/throw_delegate.h"
#include "google/cloud/storage/internal/parse_rfc3339.h"
#include <sstream>

namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
CommonMetadata MetadataParser::ParseCommonMetadata(nl::json const& json) {
  CommonMetadata result{};
  result.etag_ = json.value("etag", "");
  result.id_ = json.value("id", "");
  result.kind_ = json.value("kind", "");
  result.location_ = json.value("location", "");
  result.metadata_generation_ = ParseLongField(json, "metageneration");
  result.name_ = json.value("name", "");
  result.project_number_ = ParseLongField(json, "projectNumber");
  result.self_link_ = json.value("selfLink", "");
  result.storage_class_ = json.value("storageClass", "");
  result.time_created_ = ParseTimestampField(json, "timeCreated");
  result.time_updated_ = storage::internal::ParseRfc3339(json["updated"]);
  return result;
}

std::chrono::system_clock::time_point MetadataParser::ParseTimestampField(
    storage::internal::nl::json const& json, char const* field) {
  if (json.count(field) == 0) {
    return std::chrono::system_clock::time_point{};
  }
  return storage::internal::ParseRfc3339(json[field]);
}

std::int64_t MetadataParser::ParseLongField(
    storage::internal::nl::json const& json, char const* field) {
  if (json.count(field) == 0) {
    return 0;
  }
  auto const& f = json[field];
  if (f.is_number()) {
    return f.get<std::int64_t>();
  }
  if (f.is_string()) {
    return std::stoll(f.get_ref<std::string const&>());
  }
  std::ostringstream os;
  os << "Error parsing field <" << field
     << "> as an std::int64_t, json=" << json;
  google::cloud::internal::RaiseInvalidArgument(os.str());
}

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
