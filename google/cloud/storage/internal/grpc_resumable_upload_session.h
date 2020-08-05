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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_GRPC_RESUMABLE_UPLOAD_SESSION_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_GRPC_RESUMABLE_UPLOAD_SESSION_H

#include "google/cloud/storage/internal/grpc_client.h"
#include "google/cloud/storage/internal/resumable_upload_session.h"
#include "google/cloud/storage/version.h"

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
/// Implements the ResumableUploadSession interface for a gRPC client.
class GrpcResumableUploadSession : public ResumableUploadSession {
 public:
  explicit GrpcResumableUploadSession(std::shared_ptr<GrpcClient> client,
                                      QueryResumableUploadRequest query_request)
      : client_(std::move(client)),
        query_request_(std::move(query_request)),
        session_id_(query_request_.upload_session_url()) {}

  StatusOr<ResumableUploadResponse> UploadChunk(
      ConstBufferSequence const& payload) override;

  StatusOr<ResumableUploadResponse> UploadFinalChunk(
      ConstBufferSequence const& payload, std::uint64_t upload_size) override;

  StatusOr<ResumableUploadResponse> ResetSession() override;

  std::uint64_t next_expected_byte() const override;

  std::string const& session_id() const override;

  bool done() const override;

  StatusOr<ResumableUploadResponse> const& last_response() const override;

 private:
  /**
   * Uploads a multiple of the upload quantum bytes from @p buffers
   *
   * This function is used by both UploadChunk() and UploadFinalChunk()
   */
  StatusOr<ResumableUploadResponse> UploadGeneric(ConstBufferSequence buffers,
                                                  bool final_chunk);

  void CreateUploadWriter();

  StatusOr<ResumableUploadResponse> HandleWriteError();

  std::shared_ptr<GrpcClient> client_;
  QueryResumableUploadRequest query_request_;
  std::string session_id_;
  using UploadWriter =
      grpc::ClientWriterInterface<google::storage::v1::InsertObjectRequest>;
  std::unique_ptr<grpc::ClientContext> upload_context_;
  google::storage::v1::Object upload_object_;
  std::unique_ptr<UploadWriter> upload_writer_;

  std::uint64_t next_expected_ = 0;
  bool done_ = false;
  StatusOr<ResumableUploadResponse> last_response_;
};
}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_GRPC_RESUMABLE_UPLOAD_SESSION_H
