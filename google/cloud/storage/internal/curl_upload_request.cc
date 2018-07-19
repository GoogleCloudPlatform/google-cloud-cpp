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

#include "google/cloud/storage/internal/curl_upload_request.h"
#include "google/cloud/internal/throw_delegate.h"
#include "google/cloud/log.h"
#include "google/cloud/storage/internal/binary_data_as_debug_string.h"
#include "google/cloud/storage/internal/curl_wrappers.h"
#include <curl/multi.h>
#include <algorithm>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {

CurlUploadRequest::CurlUploadRequest()
    : headers_(nullptr, &curl_slist_free_all),
      multi_(nullptr, &curl_multi_cleanup),
      closing_(false),
      curl_closed_(false) {
  buffer_.reserve(128 * 1024);
  buffer_rdptr_ = buffer_.end();
}

void CurlUploadRequest::Flush() {
  ValidateOpen(__func__);
  handle_.FlushDebug(__func__);
  GCP_LOG(DEBUG) << __func__ << "(), curl.size=" << buffer_.size()
                 << ", curl.rdptr="
                 << std::distance(buffer_.begin(), buffer_rdptr_)
                 << ", curl.end="
                 << std::distance(buffer_.begin(), buffer_.end());
  Wait([this] { return buffer_rdptr_ == buffer_.end(); });
}

HttpResponse CurlUploadRequest::Close() {
  ValidateOpen(__func__);
  handle_.FlushDebug(__func__);
  if (curl_closed_) {
    google::cloud::internal::RaiseRuntimeError(
        "Attempting to use closed stream");
  }
  Flush();
  // Set the the closing_ flag to trigger a return 0 from the next read
  // callback, see the comments in the header file for more details.
  closing_ = true;
  // Block until that callback is made.
  Wait([this] { return curl_closed_; });

  // Now remove the handle from the CURLM* interface and wait for the response.
  auto error = curl_multi_remove_handle(multi_.get(), handle_.handle_.get());
  HandleCurlMultiErrorCode(__func__, error);

  long http_code = handle_.GetResponseCode();
  return HttpResponse{http_code, std::move(response_payload_),
                      std::move(received_headers_)};
}

void CurlUploadRequest::NextBuffer(std::string& next_buffer) {
  ValidateOpen(__func__);
  Flush();
  next_buffer.swap(buffer_);
  buffer_rdptr_ = buffer_.begin();
}

void CurlUploadRequest::ResetOptions() {
  handle_.SetOption(CURLOPT_URL, url_.c_str());
  handle_.SetOption(CURLOPT_HTTPHEADER, headers_.get());
  handle_.SetOption(CURLOPT_USERAGENT, user_agent_.c_str());
  handle_.SetWriterCallback(
      [this](void* ptr, std::size_t size, std::size_t nmemb) {
        this->response_payload_.append(static_cast<char*>(ptr), size * nmemb);
        return size * nmemb;
      });
  handle_.SetReaderCallback(
      [this](char* ptr, std::size_t size, std::size_t nmemb) {
        return this->ReadCallback(ptr, size, nmemb);
      });
  handle_.SetHeaderCallback([this](char* contents, std::size_t size,
                                   std::size_t nitems) {
    return CurlAppendHeaderData(
        received_headers_, static_cast<char const*>(contents), size * nitems);
  });
  handle_.EnableLogging(logging_enabled_);

  handle_.SetOption(CURLOPT_UPLOAD, 1L);
  handle_.SetOption(CURLOPT_CUSTOMREQUEST, "POST");
  auto error = curl_multi_add_handle(multi_.get(), handle_.handle_.get());
#if CURL_AT_LEAST_VERSION(7,32,1)
  if (error != CURLM_ADDED_ALREADY) {
    HandleCurlMultiErrorCode(__func__, error);
  }
#else
  HandleCurlMultiErrorCode(__func__, error);
#endif  // CURL_AT_LEAST_VERSION(7,32,1)
}

std::size_t CurlUploadRequest::ReadCallback(char* ptr, std::size_t size,
                                            std::size_t nmemb) {
  handle_.FlushDebug(__func__);

  std::size_t available =
      static_cast<std::size_t>(std::distance(buffer_rdptr_, buffer_.end()));
  if (available >= size * nmemb) {
    available = size * nmemb;
  }
  GCP_LOG(DEBUG) << __func__ << "() size=" << size << ", nmemb=" << nmemb
                 << ", buffer.size=" << buffer_.size()
                 << ", available=" << available << ", closed=" << closing_;
  // This transfer is closing, just return zero, that will make libcurl finish
  // any pending work, and will return the handle_ pointer from
  // curl_multi_info_read() in PerformWork(). That is the point where
  // `curl_closed_` is set.
  if (closing_) {
    return 0;
  }

  if (available == 0) {
    return CURL_READFUNC_PAUSE;
  }
  std::copy(buffer_rdptr_, buffer_rdptr_ + available, ptr);
  buffer_rdptr_ += available;
  return available;
}

int CurlUploadRequest::PerformWork() {
  // Block while there is work to do, apparently newer versions of libcurl do
  // not need this loop and curl_multi_perform() blocks until there is no more
  // work, but is it pretty harmless to keep here.
  int running_handles = 0;
  CURLMcode result;
  do {
    result = curl_multi_perform(multi_.get(), &running_handles);
    GCP_LOG(DEBUG) << __func__ << "(): running_handles=" << running_handles
                   << ", result=" << result;
  } while (result == CURLM_CALL_MULTI_PERFORM);

  // Raise an exception if the result is unexpected, otherwise return.
  HandleCurlMultiErrorCode(__func__, result);
  if (running_handles == 0) {
    // The only way we get here is if the handle "completed", and therefore the
    // transfer either failed or was successful. Pull all the messages out of
    // the info queue until we get the message about our handle.
    int remaining = 0;
    do {
      auto msg = curl_multi_info_read(multi_.get(), &remaining);
      if (msg == nullptr) {
        // Nothing to report, just terminate the search for terminated handles.
        break;
      }
      if (msg->easy_handle != handle_.handle_.get()) {
        // Raise an exception if the handle is not the right one. This should
        // never happen, but better to give some meaningful error in this case.
        std::ostringstream os;
        os << __func__ << " unknown handle returned by curl_multi_info_read()"
           << ", msg.msg=[" << msg->msg << "]"
           << ", result=[" << msg->data.result
           << "]=" << curl_easy_strerror(msg->data.result);
        google::cloud::internal::RaiseRuntimeError(os.str());
      }
      GCP_LOG(DEBUG) << __func__ << "(): msg.msg=[" << msg->msg << "], "
                     << " result=[" << msg->data.result
                     << "]=" << curl_easy_strerror(msg->data.result);
      // The transfer is done, set the state flags appropriately.
      curl_closed_ = true;
    } while (remaining > 0);
  }
  return running_handles;
}

void CurlUploadRequest::WaitForHandles() {
  CURLMcode result = curl_multi_wait(multi_.get(), nullptr, 0, 0, nullptr);
  HandleCurlMultiErrorCode(__func__, result);
}

void CurlUploadRequest::HandleCurlMultiErrorCode(char const* where,
                                                 CURLMcode result) {
  if (result == CURLM_OK) {
    return;
  }
  std::ostringstream os;
  os << where << ": unexpected error code in curl_multi_perform, [" << result
     << "]=" << curl_multi_strerror(result);
  google::cloud::internal::RaiseRuntimeError(os.str());
}

void CurlUploadRequest::ValidateOpen(char const* where) {
  if (not closing_) {
    return;
  }
  std::ostringstream os;
  os << "Attempting to use closed CurlUploadRequest in " << where;
  google::cloud::internal::RaiseRuntimeError(os.str());
}

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
