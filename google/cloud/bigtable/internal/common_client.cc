// Copyright 2018 Google Inc.
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

#include "google/cloud/bigtable/internal/common_client.h"

namespace google {
namespace cloud {
namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
namespace internal {

ConnectionRefreshState::ConnectionRefreshState(
    std::chrono::milliseconds max_conn_refresh_period)
    : max_conn_refresh_period_(max_conn_refresh_period),
      rng_(std::random_device{}()),
      timers_(std::make_shared<OutstandingTimers>()) {}

std::chrono::milliseconds ConnectionRefreshState::RandomizedRefreshDelay() {
  std::lock_guard<std::mutex> lk(mu_);
  return std::chrono::milliseconds(
      std::uniform_int_distribution<decltype(max_conn_refresh_period_)::rep>(
          1, max_conn_refresh_period_.count())(rng_));
}

void ScheduleChannelRefresh(
    std::shared_ptr<CompletionQueue> const& cq,
    std::shared_ptr<ConnectionRefreshState> const& state,
    std::shared_ptr<grpc::Channel> const& channel) {
  // The timers will only hold weak pointers to the channel or to the
  // completion queue, so if either of them are destroyed, the timer chain
  // will simply not continue.
  std::weak_ptr<grpc::Channel> weak_channel(channel);
  std::weak_ptr<CompletionQueue> weak_cq(cq);
  using TimerFuture = future<StatusOr<std::chrono::system_clock::time_point>>;
  auto timer_future =
      cq->MakeRelativeTimer(state->RandomizedRefreshDelay())
          .then([weak_channel, weak_cq, state](TimerFuture fut) {
            if (!fut.get()) {
              // Timer cancelled.
              return;
            }
            auto channel = weak_channel.lock();
            if (!channel) return;
            auto cq = weak_cq.lock();
            if (!cq) return;
            cq->AsyncWaitConnectionReady(
                  channel,
                  std::chrono::system_clock::now() + kConnectionReadyTimeout)
                .then([weak_channel, weak_cq, state](future<Status> fut) {
                  auto conn_status = fut.get();
                  if (!conn_status.ok()) {
                    GCP_LOG(WARNING) << "Failed to refresh connection. Error: "
                                     << conn_status;
                  }
                  auto channel = weak_channel.lock();
                  if (!channel) return;
                  auto cq = weak_cq.lock();
                  if (!cq) return;
                  ScheduleChannelRefresh(cq, state, channel);
                });
          });
  state->timers().RegisterTimer(std::move(timer_future));
}

void OutstandingTimers::RegisterTimer(future<void> fut) {
  std::unique_lock<std::mutex> lk(mu_);
  if (shutdown_) {
    lk.unlock();
    fut.cancel();
    return;
  }

  timers_.emplace_front(future<void>());
  auto iter = timers_.begin();
  lk.unlock();
  std::weak_ptr<OutstandingTimers> weak_self(shared_from_this());
  // `iter` remains valid because the list element which it points to will only
  // be erased by the following continuation.
  *iter = fut.then([weak_self, iter](future<void>) {
    auto self = weak_self.lock();
    if (!self) return;
    std::lock_guard<std::mutex> lk(self->mu_);
    self->timers_.erase(iter);
  });
}

void OutstandingTimers::CancelAll() {
  std::vector<future<void>> to_cancel;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (shutdown_) {
      // Already cancelled
      return;
    }
    shutdown_ = true;
    // We don't want to fire the timer continuations with the lock held to avoid
    // deadlocks, so we shouldn't call `cancel()` here. We can't erase the whole
    // `timers_` list because we don't want to invalidate the iterators, which
    // we handed over to the timers' continuations, so we leave the elements in
    // the list, but we `std::move()` out their content. The cancelled timers
    // will eventually remove the list elements.
    for (auto& fut : timers_) {
      to_cancel.emplace_back(std::move(fut));
    }
  }
  for (auto& fut : to_cancel) {
    fut.cancel();
  }
}

}  // namespace internal
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google
