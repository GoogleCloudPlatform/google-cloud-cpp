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
  // will simply not continue. Unfortunately, that means that some stray
  // timers may remain in the `CompletionQueue` for a while, but this is
  // generally unavoidable because there is no way to cancel individual
  // timers.
  std::weak_ptr<grpc::Channel> weak_channel(channel);
  std::weak_ptr<CompletionQueue> weak_cq(cq);
  using TimerFuture = future<StatusOr<std::chrono::system_clock::time_point>>;
  // A dummy object which allows us to pass the timer deleter to the timer's
  // continuation after it is created. This, unfortunately, is the only possible
  // order of construction.
  struct TimerHandleHolder {
    OutstandingTimers::TimerDeleter deleter;
  };
  auto deleter_holder = std::make_shared<TimerHandleHolder>();
  auto timer_future =
      cq->MakeRelativeTimer(state->RandomizedRefreshDelay())
          .then([weak_channel, weak_cq, state,
                 deleter_holder](TimerFuture fut) {
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
  deleter_holder->deleter =
      state->timers().RegisterTimer(std::move(timer_future));
}

OutstandingTimers::TimerDeleter OutstandingTimers::RegisterTimer(
    future<void> fut) {
  std::unique_lock<std::mutex> lk(mu_);
  if (cancel_all_) {
    lk.unlock();
    fut.cancel();
  }
  timers_.emplace_back(std::move(fut));
  auto iter = --timers_.end();
  std::weak_ptr<OutstandingTimers> weak_self(shared_from_this());
  return std::shared_ptr<void>(
      // Using `this` here is completely arbitrary. It could have been
      // 0xdeadbeef. The address is not touched anyway.
      reinterpret_cast<void*>(this), [iter, weak_self](void*) {
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
    if (cancel_all_) {
      // Already cancelled
      return;
    }
    cancel_all_ = true;
    // We don't want to fire the callbacks with the lock held to avoid
    // deadlocks. We can't erase the whole `timers_` because we don't want to
    // invalidate the iterators, which we handed over to users, so we leave the
    // elements in the list, but we move out their content. The cancelled timers
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
