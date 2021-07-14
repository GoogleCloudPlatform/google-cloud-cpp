// Copyright 2021 Google LLC
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

#include "google/cloud/storage/object_read_stream.h"
#include "google/cloud/log.h"
#include "absl/memory/memory.h"

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
static_assert(std::is_move_assignable<ObjectReadStream>::value,
              "storage::ObjectReadStream must be move assignable.");
static_assert(std::is_move_constructible<ObjectReadStream>::value,
              "storage::ObjectReadStream must be move constructible.");

ObjectReadStream::ObjectReadStream()
    : ObjectReadStream(absl::make_unique<internal::ObjectReadStreambuf>(
          internal::ReadObjectRangeRequest("", ""),
          Status(StatusCode::kUnimplemented, "null stream"))) {}

ObjectReadStream::ObjectReadStream(ObjectReadStream&& rhs) noexcept
    : std::basic_istream<char>(std::move(rhs)), buf_(std::move(rhs.buf_)) {
  rhs.set_rdbuf(nullptr);
  set_rdbuf(buf_.get());
}

ObjectReadStream::~ObjectReadStream() {
  if (!IsOpen()) {
    return;
  }
#if GOOGLE_CLOUD_CPP_HAVE_EXCEPTIONS
  try {
    Close();
  } catch (std::exception const& ex) {
    GCP_LOG(INFO) << "Ignored exception while trying to close stream: "
                  << ex.what();
  } catch (...) {
    GCP_LOG(INFO) << "Ignored unknown exception while trying to close stream";
  }
#else
  Close();
#endif  // GOOGLE_CLOUD_CPP_HAVE_EXCEPTIONS
}

void ObjectReadStream::Close() {
  if (!IsOpen()) {
    return;
  }
  buf_->Close();
  if (!status().ok()) {
    setstate(std::ios_base::badbit);
  }
}

}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
