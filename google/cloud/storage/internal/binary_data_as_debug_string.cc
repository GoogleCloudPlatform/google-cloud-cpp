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

#include "google/cloud/storage/internal/binary_data_as_debug_string.h"
#include <cctype>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
std::string BinaryDataAsDebugString(char const* data, std::size_t size) {
  std::string result;
  std::size_t text_width = 24;
  std::string text_column(text_width, ' ');
  std::string hex_column(2 * text_width, ' ');

  auto flush = [&result, &text_column, &hex_column, text_width] {
    result += text_column;
    result += ' ';
    result += hex_column;
    result += '\n';
    text_column = std::string(text_width, ' ');
    hex_column = std::string(2 * text_width, ' ');
  };

  std::size_t count = 0;
  for (char const* c = data; c != data + size; ++c) {
    if (std::isprint(*c) != 0) {
      text_column[count] = *c;
    } else {
      text_column[count] = '.';
    }
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned char>(*c));
    hex_column[2 * count] = buf[0];
    hex_column[2 * count + 1] = buf[1];
    ++count;
    if (count == text_width) {
      flush();
      count = 0;
    }
  }
  if (count != 0) {
    flush();
  }
  return result;
}
}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
