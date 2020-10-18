// Copyright 2020 Google LLC
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

#include "google/cloud/pubsub/internal/streaming_subscription_batch_source.h"
#include "google/cloud/internal/async_retry_loop.h"
#include "google/cloud/log.h"
#include <ostream>

namespace google {
namespace cloud {
namespace pubsub_internal {
inline namespace GOOGLE_CLOUD_CPP_PUBSUB_NS {

using google::cloud::internal::Idempotency;

void StreamingSubscriptionBatchSource::Start(BatchCallback callback) {
  std::unique_lock<std::mutex> lk(mu_);
  if (callback_) return;
  callback_ = std::move(callback);
  lk.unlock();

  shutdown_manager_->StartOperation(__func__, "stream", [this] {
    StartStream(retry_policy_->clone(), backoff_policy_->clone());
  });
}

void StreamingSubscriptionBatchSource::Shutdown() {
  std::unique_lock<std::mutex> lk(mu_);
  if (shutdown_ || !stream_) return;
  shutdown_ = true;
  if (stream_state_ != StreamState::kActive) return;
  stream_->Cancel();
}

void StreamingSubscriptionBatchSource::AckMessage(std::string const& ack_id) {
  std::unique_lock<std::mutex> lk(mu_);
  ack_queue_.push_back(ack_id);
  DrainQueues(std::move(lk));
}

void StreamingSubscriptionBatchSource::NackMessage(std::string const& ack_id) {
  std::unique_lock<std::mutex> lk(mu_);
  nack_queue_.push_back(ack_id);
  DrainQueues(std::move(lk));
}

void StreamingSubscriptionBatchSource::BulkNack(
    std::vector<std::string> ack_ids) {
  std::unique_lock<std::mutex> lk(mu_);
  for (auto& a : ack_ids) {
    nack_queue_.push_back(std::move(a));
  }
  DrainQueues(std::move(lk));
}

void StreamingSubscriptionBatchSource::ExtendLeases(
    std::vector<std::string> ack_ids, std::chrono::seconds extension) {
  std::unique_lock<std::mutex> lk(mu_);
  for (auto& a : ack_ids) {
    deadlines_queue_.emplace_back(std::move(a), extension);
  }
  DrainQueues(std::move(lk));
}

void StreamingSubscriptionBatchSource::StartStream(
    std::shared_ptr<pubsub::RetryPolicy> retry_policy,
    std::shared_ptr<pubsub::BackoffPolicy> backoff_policy) {
  // Starting a stream is a 4 step process.
  // 1. Create a new SubscriberStub::AsyncPullStream object.
  // 2. Call Start() on it, which is asynchronous, which might fail, but rarel
  //    does
  // 3. Call Write() on it, which is also asynchronous and almost always
  //    succeeds, could fail if the endpoint is invalid
  // 4. Call Read() on it, which is also asynchronous, and it is the first
  //    change to get errors such as kPermissionDenied, or kNotFound.
  // Once Read() completes we can repeatedly call Read() and/or Write().
  // Because steps 2 through 4 may fail with transient errors we need to wrap
  // these steps in an asynchronous retry loop.

  auto request = InitialRequest();
  auto stream = stub_->AsyncStreamingPull(
      cq_, absl::make_unique<grpc::ClientContext>(), request);
  if (!stream) {
    shutdown_manager_->MarkAsShutdown(
        __func__, Status(StatusCode::kUnknown, "null stream"));
    return;
  }

  RetryLoopState rs{std::move(stream), std::move(retry_policy),
                    std::move(backoff_policy)};

  auto weak = WeakFromThis();
  rs.stream->Start().then([weak, rs, request](future<bool> f) {
    if (auto s = weak.lock()) s->OnStart(rs, request, f.get());
  });
}

google::pubsub::v1::StreamingPullRequest
StreamingSubscriptionBatchSource::InitialRequest() const {
  google::pubsub::v1::StreamingPullRequest request;
  request.set_subscription(subscription_full_name_);
  request.set_client_id(client_id_);
  request.set_max_outstanding_bytes(max_outstanding_bytes_);
  request.set_max_outstanding_messages(max_outstanding_messages_);
  auto const deadline =
      std::max(std::chrono::seconds(10),
               std::min(std::chrono::seconds(600), max_deadline_time_))
          .count();
  request.set_stream_ack_deadline_seconds(static_cast<std::int32_t>(deadline));
  return request;
}

void StreamingSubscriptionBatchSource::OnStart(
    RetryLoopState rs, google::pubsub::v1::StreamingPullRequest const& request,
    bool ok) {
  auto weak = WeakFromThis();
  if (!ok) {
    rs.stream->Finish().then([weak, rs](future<Status> f) mutable {
      if (auto s = weak.lock()) s->OnInitialFinish(std::move(rs), f.get());
    });
    return;
  }
  rs.stream->Write(request, grpc::WriteOptions{}.set_write_through())
      .then([weak, rs](future<bool> f) mutable {
        if (auto s = weak.lock()) s->OnInitialWrite(std::move(rs), f.get());
      });
}

void StreamingSubscriptionBatchSource::OnInitialWrite(RetryLoopState rs,
                                                      bool ok) {
  auto weak = WeakFromThis();
  if (!ok) {
    rs.stream->Finish().then([weak, rs](future<Status> f) {
      if (auto s = weak.lock()) s->OnInitialFinish(std::move(rs), f.get());
    });
    return;
  }
  rs.stream->Read().then(
      [weak, rs](
          future<absl::optional<google::pubsub::v1::StreamingPullResponse>> f) {
        if (auto s = weak.lock()) s->OnInitialRead(std::move(rs), f.get());
      });
}

void StreamingSubscriptionBatchSource::OnInitialRead(
    RetryLoopState rs,
    absl::optional<google::pubsub::v1::StreamingPullResponse> response) {
  auto weak = WeakFromThis();
  if (!response.has_value()) {
    rs.stream->Finish().then([weak, rs](future<Status> f) {
      if (auto s = weak.lock()) s->OnInitialFinish(std::move(rs), f.get());
    });
    return;
  }

  std::unique_lock<std::mutex> lk(mu_);
  ChangeState(lk, StreamState::kActive, __func__, "success");
  status_ = Status{};
  stream_ = std::move(rs.stream);
  lk.unlock();
  auto const scheduled =
      shutdown_manager_->StartOperation(__func__, "read", [&] {
        shutdown_manager_->FinishedOperation("read");
        OnRead(std::move(response));
      });
  if (!scheduled) {
    lk.lock();
    stream_->Cancel();
    ShutdownStream(std::move(lk), "early-shutdown");
  }
}

void StreamingSubscriptionBatchSource::OnInitialFinish(RetryLoopState rs,
                                                       Status status) {
  if (!rs.retry_policy->OnFailure(status)) {
    shutdown_manager_->FinishedOperation("stream");
    shutdown_manager_->MarkAsShutdown(__func__, std::move(status));
    return;
  }
  auto weak = WeakFromThis();
  using F = future<StatusOr<std::chrono::system_clock::time_point>>;
  cq_.MakeRelativeTimer(rs.backoff_policy->OnCompletion())
      .then([weak, rs, status](F) mutable {
        if (auto s = weak.lock()) {
          s->OnBackoff(std::move(rs), std::move(status));
        }
      });
}

void StreamingSubscriptionBatchSource::OnBackoff(RetryLoopState rs,
                                                 Status status) {
  if (rs.retry_policy->IsExhausted()) {
    shutdown_manager_->FinishedOperation("stream");
    shutdown_manager_->MarkAsShutdown(__func__, std::move(status));
    return;
  }
  auto const scheduled =
      shutdown_manager_->StartOperation(__func__, "retry", [&] {
        shutdown_manager_->FinishedOperation("retry");
        StartStream(std::move(rs.retry_policy), std::move(rs.backoff_policy));
      });
  if (!scheduled) {
    shutdown_manager_->FinishedOperation("stream");
    shutdown_manager_->MarkAsShutdown(__func__, std::move(status));
  }
}

void StreamingSubscriptionBatchSource::ReadLoop() {
  std::unique_lock<std::mutex> lk(mu_);
  if (stream_state_ != StreamState::kActive) return;
  pending_read_ = true;
  auto stream = stream_;
  lk.unlock();
  auto weak = WeakFromThis();
  stream->Read().then(
      [weak](
          future<absl::optional<google::pubsub::v1::StreamingPullResponse>> f) {
        if (auto self = weak.lock()) self->OnRead(f.get());
      });
  lk.lock();
}

void StreamingSubscriptionBatchSource::OnRead(
    absl::optional<google::pubsub::v1::StreamingPullResponse> response) {
  auto weak = WeakFromThis();
  std::unique_lock<std::mutex> lk(mu_);
  pending_read_ = false;
  if (response && stream_state_ == StreamState::kActive && !shutdown_) {
    lk.unlock();
    callback_(*std::move(response));
    cq_.RunAsync([weak] {
      if (auto self = weak.lock()) self->ReadLoop();
    });
    return;
  }
  ShutdownStream(std::move(lk), response ? "state" : "read error");
}

void StreamingSubscriptionBatchSource::ShutdownStream(
    std::unique_lock<std::mutex> lk, char const* reason) {
  if (stream_state_ != StreamState::kActive &&
      stream_state_ != StreamState::kDisconnecting) {
    return;
  }
  ChangeState(lk, StreamState::kDisconnecting, __func__, reason);
  if (pending_read_ || pending_write_) return;

  auto stream = stream_;
  ChangeState(lk, StreamState::kFinishing, __func__, reason);
  lk.unlock();
  auto weak = WeakFromThis();
  // There are no pending reads or writes, and something (probable a read or
  // write error) recommends we shutdown the stream
  stream->Finish().then([weak](future<Status> f) {
    if (auto self = weak.lock()) self->OnFinish(f.get());
  });
}

void StreamingSubscriptionBatchSource::OnFinish(Status status) {
  std::unique_lock<std::mutex> lk(mu_);
  status_ = std::move(status);
  stream_.reset();
  ChangeState(lk, StreamState::kNull, __func__, "done");
  if (shutdown_manager_->FinishedOperation("stream")) return;
  lk.unlock();
  shutdown_manager_->StartOperation(__func__, "stream", [this] {
    StartStream(retry_policy_->clone(), backoff_policy_->clone());
  });
}

void StreamingSubscriptionBatchSource::DrainQueues(
    std::unique_lock<std::mutex> lk) {
  if (ack_queue_.empty() && nack_queue_.empty() && deadlines_queue_.empty()) {
    return;
  }
  if (stream_state_ != StreamState::kActive || pending_write_) return;
  auto stream = stream_;
  pending_write_ = true;

  std::vector<std::string> acks;
  acks.swap(ack_queue_);
  std::vector<std::string> nacks;
  nacks.swap(nack_queue_);
  std::vector<std::pair<std::string, std::chrono::seconds>> deadlines;
  deadlines.swap(deadlines_queue_);
  lk.unlock();

  google::pubsub::v1::StreamingPullRequest request;
  for (auto& a : acks) request.add_ack_ids(std::move(a));
  for (auto& n : nacks) {
    request.add_modify_deadline_ack_ids(std::move(n));
    request.add_modify_deadline_seconds(0);
  }
  for (auto& d : deadlines) {
    request.add_modify_deadline_ack_ids(std::move(d.first));
    request.add_modify_deadline_seconds(
        static_cast<std::int32_t>(d.second.count()));
  }
  // Note that we do not use `AsyncRetryLoop()` here. The ack/nack pipeline is
  // best-effort anyway, there is no guarantee that the server will act on any
  // of these.
  auto weak = WeakFromThis();
  stream->Write(request, grpc::WriteOptions{}).then([weak](future<bool> f) {
    if (auto self = weak.lock()) self->OnWrite(f.get());
  });
}

void StreamingSubscriptionBatchSource::OnWrite(bool ok) {
  std::unique_lock<std::mutex> lk(mu_);
  pending_write_ = false;
  if (ok && stream_state_ == StreamState::kActive && !shutdown_) {
    DrainQueues(std::move(lk));
    return;
  }
  ShutdownStream(std::move(lk), ok ? "state" : "write error");
}

std::ostream& operator<<(std::ostream& os,
                         StreamingSubscriptionBatchSource::StreamState s) {
  using State = StreamingSubscriptionBatchSource::StreamState;
  switch (s) {
    case State::kNull:
      os << "kNull";
      break;
    case State::kActive:
      os << "kActive";
      break;
    case State::kDisconnecting:
      os << "kDisconnecting";
      break;
    case State::kFinishing:
      os << "kFinishing";
      break;
  }
  return os;
}

void StreamingSubscriptionBatchSource::ChangeState(
    std::unique_lock<std::mutex> const&, StreamState s, char const* where,
    char const* reason) {
  GCP_LOG(DEBUG) << where << " (" << reason << ") " << stream_state_ << ":" << s
                 << " read=" << pending_read_ << " write=" << pending_write_
                 << " shutdown=" << shutdown_
                 << " stream=" << (stream_ ? "not-null" : "null")
                 << " status=" << status_;
  stream_state_ = s;
}

}  // namespace GOOGLE_CLOUD_CPP_PUBSUB_NS
}  // namespace pubsub_internal
}  // namespace cloud
}  // namespace google
