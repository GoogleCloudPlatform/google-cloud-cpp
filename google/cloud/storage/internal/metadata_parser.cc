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

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
std::chrono::system_clock::time_point ParseTimestampField(
    nl::json const& json, char const* field_name) {
  if (json.count(field_name) == 0) {
    return std::chrono::system_clock::time_point{};
  }
  return ParseRfc3339(json[field_name]);
}

std::int64_t ParseLongField(nl::json const& json, char const* field_name) {
  if (json.count(field_name) == 0) {
    return 0;
  }
  auto const& f = json[field_name];
  if (f.is_number()) {
    return f.get<std::int64_t>();
  }
  if (f.is_string()) {
    return std::stoll(f.get_ref<std::string const&>());
  }
  std::ostringstream os;
  os << "Error parsing field <" << field_name
     << "> as an std::int64_t, json=" << json;
  google::cloud::internal::RaiseInvalidArgument(os.str());
}

std::uint64_t ParseUnsignedLongField(nl::json const& json,
                                     char const* field_name) {
  if (json.count(field_name) == 0) {
    return 0;
  }
  auto const& f = json[field_name];
  if (f.is_number()) {
    return f.get<std::uint64_t>();
  }
  if (f.is_string()) {
    return std::stoull(f.get_ref<std::string const&>());
  }
  std::ostringstream os;
  os << "Error parsing field <" << field_name
     << "> as an std::uint64_t, json=" << json;
  google::cloud::internal::RaiseInvalidArgument(os.str());
}

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
