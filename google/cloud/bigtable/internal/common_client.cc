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
namespace {

std::chrono::milliseconds RandomizedRefreshDelay(
    std::chrono::milliseconds max_conn_refresh_period) {
  static std::mutex mu;
  static google::cloud::internal::DefaultPRNG rng(std::random_device{}());
  std::lock_guard<std::mutex> lk(mu);
  return std::chrono::milliseconds(
      std::uniform_int_distribution<decltype(max_conn_refresh_period)::rep>(
          1, max_conn_refresh_period.count())(rng));
}

}  // namespace

void ScheduleChannelRefresh(std::shared_ptr<CompletionQueue> const& cq,
                            std::shared_ptr<grpc::Channel> const& channel,
                            std::chrono::milliseconds max_conn_refresh_period) {
  // The timers will only hold weak pointers to the channel or to the
  // completion queue, so if either of them are destroyed, the timer chain
  // will simply not continue. Unfortunately, that means that some stray
  // timers may remain in the `CompletionQueue` for a while, but this is
  // generally unavoidable because there is no way to cancel individual
  // timers.
  std::weak_ptr<grpc::Channel> weak_channel(channel);
  std::weak_ptr<CompletionQueue> weak_cq(cq);
  using TimerFuture = future<StatusOr<std::chrono::system_clock::time_point>>;
  cq->MakeRelativeTimer(RandomizedRefreshDelay(max_conn_refresh_period))
      .then([weak_channel, weak_cq, max_conn_refresh_period](TimerFuture fut) {
        if (!fut.get()) {
          // Timer cancelled.
          return;
        }
        auto channel = weak_channel.lock();
        if (!channel) return;
        auto cq = weak_cq.lock();
        if (!cq) return;
        cq->AsyncWaitConnectionReady(channel, std::chrono::system_clock::now() +
                                                  kConnectionReadyTimeout)
            .then([weak_channel, weak_cq,
                   max_conn_refresh_period](future<Status> fut) {
              auto conn_status = fut.get();
              if (!conn_status.ok()) {
                GCP_LOG(WARNING)
                    << "Failed to refresh connection. Error: " << conn_status;
              }
              auto channel = weak_channel.lock();
              if (!channel) return;
              auto cq = weak_cq.lock();
              if (!cq) return;
              ScheduleChannelRefresh(cq, channel, max_conn_refresh_period);
            });
      });
}

}  // namespace internal
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google
