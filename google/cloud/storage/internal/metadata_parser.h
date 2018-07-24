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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_METADATA_PARSER_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_METADATA_PARSER_H_

#include "google/cloud/storage/internal/nljson.h"
#include <chrono>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
/**
 * Parse a boolean field, even if it is represented by a string type in the JSON
 * object.
 */
bool ParseBoolField(nl::json const& json, char const* field_name);

/**
 * Parse an integer field, even if it is represented by a string type in the
 * JSON object.
 */
std::int32_t ParseIntField(nl::json const& json, char const* field_name);

/**
 * Parse an unsigned integer field, even if it is represented by a string type
 * in the JSON object.
 */
std::uint32_t ParseUnsignedIntField(nl::json const& json,
                                    char const* field_name);

/**
 * Parse a long integer field, even if it is represented by a string type in
 * the JSON object.
 */
std::int64_t ParseLongField(nl::json const& json, char const* field_name);

/**
 * Parse an unsigned long integer field, even if it is represented by a string
 * type in the JSON object.
 */
std::uint64_t ParseUnsignedLongField(nl::json const& json,
                                     char const* field_name);

/**
 * Parse a RFC 3339 timestamp.
 */
std::chrono::system_clock::time_point ParseTimestampField(
    nl::json const& json, char const* field_name);

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_METADATA_PARSER_H_
