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

#include "google/cloud/pubsub/internal/batching_publisher_connection.h"
#include "google/cloud/internal/async_retry_loop.h"
#include <numeric>

namespace google {
namespace cloud {
namespace pubsub_internal {
inline namespace GOOGLE_CLOUD_CPP_PUBSUB_NS {

// A helper callable to handle a response, it is a bit large for a lambda, and
// we need move-capture anyways.
struct Batch {
  // We are going to use the completion queue as an executor, so we might as
  // well name it as one.
  google::cloud::CompletionQueue executor;
  std::vector<promise<StatusOr<std::string>>> waiters;
  std::weak_ptr<BatchingPublisherConnection> weak;

  void operator()(future<StatusOr<google::pubsub::v1::PublishResponse>> f) {
    auto response = f.get();
    if (!response) {
      SatisfyAllWaiters(response.status());
      if (auto batcher = weak.lock()) batcher->DiscardCorked(response.status());
      return;
    }
    if (static_cast<std::size_t>(response->message_ids_size()) !=
        waiters.size()) {
      SatisfyAllWaiters(
          Status(StatusCode::kUnknown, "mismatched message id count"));
      return;
    }
    struct SetValue {
      promise<StatusOr<std::string>> waiter;
      std::string value;
      void operator()() { waiter.set_value(std::move(value)); }
    };
    int idx = 0;
    for (auto& w : waiters) {
      executor.RunAsync(SetValue{std::move(w), response->message_ids(idx++)});
    }
    if (auto batcher = weak.lock()) batcher->UnCork();
  }

  void SatisfyAllWaiters(Status const& status) {
    struct SetStatus {
      promise<StatusOr<std::string>> waiter;
      Status status;
      void operator()() { waiter.set_value(std::move(status)); }
    };
    for (auto& w : waiters) {
      executor.RunAsync(SetStatus{std::move(w), status});
    }
  }
};

future<StatusOr<std::string>> BatchingPublisherConnection::Publish(
    pubsub::Message m) {
  promise<StatusOr<std::string>> p;
  auto f = p.get_future();
  std::unique_lock<std::mutex> lk(mu_);
  if (!corked_status_.ok()) {
    struct MoveCapture {
      promise<StatusOr<std::string>> p;
      Status status;
      void operator()() { p.set_value(std::move(status)); }
    };
    cq_.RunAsync(MoveCapture{std::move(p), corked_status_});
    return f;
  }
  pending_.push_back(Item{std::move(p), std::move(m)});
  MaybeFlush(std::move(lk));
  return f;
}

void BatchingPublisherConnection::Flush() {
  FlushImpl(std::unique_lock<std::mutex>(mu_));
}

void BatchingPublisherConnection::ResumePublish(std::string const& key) {
  if (ordering_key_ != key) return;
  UnCork();
}

void BatchingPublisherConnection::UnCork() {
  std::unique_lock<std::mutex> lk(mu_);
  corked_ = false;
  corked_status_ = {};
  MaybeFlush(std::move(lk));
}

void BatchingPublisherConnection::DiscardCorked(Status const& status) {
  auto pending = [&] {
    std::unique_lock<std::mutex> lk(mu_);
    corked_ = true;
    corked_status_ = status;
    std::vector<Item> tmp;
    tmp.swap(pending_);
    return tmp;
  }();
  for (auto& p : pending) {
    struct MoveCapture {
      promise<StatusOr<std::string>> p;
      Status status;
      void operator()() { p.set_value(std::move(status)); }
    };
    cq_.RunAsync(MoveCapture{std::move(p.response), status});
  }
}

void BatchingPublisherConnection::MaybeFlush(std::unique_lock<std::mutex> lk) {
  if (pending_.size() >= options_.maximum_batch_message_count()) {
    FlushImpl(std::move(lk));
    return;
  }
  auto const bytes =
      std::accumulate(pending_.begin(), pending_.end(), std::size_t{0},
                      [](std::size_t a, Item const& b) {
                        return a + pubsub_internal::MessageSize(b.message);
                      });
  if (bytes >= options_.maximum_batch_bytes()) {
    FlushImpl(std::move(lk));
    return;
  }
  // If the batch is empty obviously we do not need a timer, and if it has more
  // than one element then we have setup a timer previously and there is no need
  // to set it again.
  if (pending_.size() != 1U) return;
  auto const expiration = batch_expiration_ =
      std::chrono::system_clock::now() + options_.maximum_hold_time();
  lk.unlock();
  // We need a weak_ptr<> because this class owns the completion queue,
  // creating a lambda with a shared_ptr<> owning this class would create a
  // cycle.  Unfortunately some older compiler/libraries lack
  // `weak_from_this()`.
  auto weak = std::weak_ptr<BatchingPublisherConnection>(shared_from_this());
  // Note that at this point the lock is released, so whether the timer
  // schedules later on schedules in this thread has no effect.
  cq_.MakeDeadlineTimer(expiration)
      .then([weak](future<StatusOr<std::chrono::system_clock::time_point>>) {
        if (auto self = weak.lock()) self->OnTimer();
      });
}

void BatchingPublisherConnection::OnTimer() {
  std::unique_lock<std::mutex> lk(mu_);
  if (std::chrono::system_clock::now() < batch_expiration_) {
    // We may get many "old" timers for batches that have already flushed due to
    // size. Trying to cancel these timers is a bit hopeless, they might trigger
    // even if we attempt to cancel them. This test is more robust.
    return;
  }
  FlushImpl(std::move(lk));
}

void BatchingPublisherConnection::FlushImpl(std::unique_lock<std::mutex> lk) {
  if (pending_.empty() || corked_) return;

  auto context = absl::make_unique<grpc::ClientContext>();

  Batch batch;
  batch.executor = cq_;
  batch.waiters.reserve(pending_.size());
  batch.weak = shared_from_this();
  google::pubsub::v1::PublishRequest request;
  request.set_topic(topic_full_name_);
  request.mutable_messages()->Reserve(static_cast<int>(pending_.size()));

  for (auto& i : pending_) {
    batch.waiters.push_back(std::move(i.response));
    *request.add_messages() = pubsub_internal::ToProto(std::move(i.message));
  }
  pending_.clear();
  corked_ = !ordering_key_.empty();
  lk.unlock();

  connection_->Publish({std::move(request)}).then(std::move(batch));
}

}  // namespace GOOGLE_CLOUD_CPP_PUBSUB_NS
}  // namespace pubsub_internal
}  // namespace cloud
}  // namespace google
