// Copyright 2017 Google Inc.
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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_INTERNAL_COMMON_CLIENT_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_INTERNAL_COMMON_CLIENT_H

#include "google/cloud/bigtable/client_options.h"
#include "google/cloud/bigtable/version.h"
#include "google/cloud/connection_options.h"
#include "google/cloud/internal/random.h"
#include "google/cloud/log.h"
#include "google/cloud/status_or.h"
#include <grpcpp/grpcpp.h>

namespace google {
namespace cloud {
namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {
namespace internal {

/**
 * Refactor implementation of `bigtable::{Data,Admin,InstanceAdmin}Client`.
 *
 * All the clients need to keep a collection (sometimes with a single element)
 * of channels, update the collection when needed and round-robin across the
 * channels. At least `bigtable::DataClient` needs to optimize the creation of
 * the stub objects.
 *
 * The class exposes the channels because they are needed for clients that
 * use more than one type of Stub.
 *
 * @tparam Traits encapsulates variations between the clients.  Currently, which
 *   `*_endpoint()` member function is used.
 * @tparam Interface the gRPC object returned by `Stub()`.
 */
template <typename Traits, typename Interface>
class CommonClient {
 public:
  //@{
  /// @name Type traits.
  using StubPtr = std::shared_ptr<typename Interface::StubInterface>;
  using ChannelPtr = std::shared_ptr<grpc::Channel>;
  //@}

  explicit CommonClient(bigtable::ClientOptions options)
      : options_(std::move(options)),
        rng_(google::cloud::internal::MakeDefaultPRNG()),
        current_index_(0),
        background_threads_(
            google::cloud::internal::DefaultBackgroundThreads(1)) {}

  /**
   * Reset the channel and stub.
   *
   * This is just used for testing at the moment.  In the future, we expect that
   * the channel and stub will need to be reset under some error conditions
   * and/or when the credentials require explicit refresh.
   */
  void reset() {
    std::lock_guard<std::mutex> lk(mu_);
    stubs_.clear();
  }

  /// Return the next Stub to make a call.
  StubPtr Stub() {
    std::unique_lock<std::mutex> lk(mu_);
    CheckConnections(lk);
    auto stub = stubs_[GetIndex()];
    return stub;
  }

  /// Return the next Channel to make a call.
  ChannelPtr Channel() {
    std::unique_lock<std::mutex> lk(mu_);
    CheckConnections(lk);
    auto channel = channels_[GetIndex()];
    return channel;
  }

  ~CommonClient() {
    // Make sure all timers finish before we start destroying structures which
    // the timers potentially touch.
    background_threads_->cq().CancelAll();
  }

 private:
  /// Make sure the connections exit, and create them if needed.
  void CheckConnections(std::unique_lock<std::mutex>& lk) {
    if (!stubs_.empty()) {
      return;
    }
    // Release the lock while making remote calls.  gRPC uses the current
    // thread to make remote connections (and probably authenticate), holding
    // a lock for long operations like that is a bad practice.  Releasing
    // the lock here can result in wasted work, but that is a smaller problem
    // than a deadlock or an unbounded priority inversion.
    // Note that only one connection per application is created by gRPC, even
    // if multiple threads are calling this function at the same time. gRPC
    // only opens one socket per destination+attributes combo, we artificially
    // introduce attributes in the implementation of CreateChannelPool() to
    // create one socket per element in the pool.
    lk.unlock();
    auto channels = CreateChannelPool();
    std::vector<StubPtr> tmp;
    std::transform(channels.begin(), channels.end(), std::back_inserter(tmp),
                   [](std::shared_ptr<grpc::Channel> ch) {
                     return Interface::NewStub(ch);
                   });
    lk.lock();
    if (stubs_.empty()) {
      channels.swap(channels_);
      tmp.swap(stubs_);
      current_index_ = 0;
    } else {
      // Some other thread created the pool and saved it in `stubs_`. The work
      // in this thread was superfluous. We release the lock while clearing the
      // channels to minimize contention.
      lk.unlock();
      tmp.clear();
      channels.clear();
      lk.lock();
    }
  }

  std::shared_ptr<grpc::Channel> CreateChannel(std::size_t idx) {
    auto args = options_.channel_arguments();
    if (!options_.connection_pool_name().empty()) {
      args.SetString("cbt-c++/connection-pool-name",
                     options_.connection_pool_name());
    }
    args.SetInt("cbt-c++/connection-pool-id", static_cast<int>(idx));
    auto res = grpc::CreateCustomChannel(Traits::Endpoint(options_),
                                         options_.credentials(), args);
    if (options_.max_conn_refresh_period().count() == 0) {
      return res;
    }
    std::chrono::seconds next_replace_after(
        std::uniform_int_distribution<std::chrono::seconds::rep>(
            1, options_.max_conn_refresh_period().count())(rng_));
    background_threads_->cq()
        .MakeRelativeTimer(next_replace_after)
        .then([this, idx](
                  future<StatusOr<std::chrono::system_clock::time_point>> fut) {
          if (!fut.get()) {
            // Timer cancelled.
            return;
          }
          auto channel = CreateChannel(idx);
          // This is blocking, but it's not a problem given that we're only
          // blocking a CompletionQueue used solely for refreshing connections.
          if (!channel->WaitForConnected(std::chrono::system_clock::now() +
                                         std::chrono::seconds(1))) {
            GCP_LOG(WARNING)
                << "Failed to connect to " << Traits::Endpoint(options_)
                << ". Skipping preemptive connection refresh";
          }
          ReplaceChannel(idx, std::move(channel));
        });
    return res;
  }

  std::vector<std::shared_ptr<grpc::Channel>> CreateChannelPool() {
    std::vector<std::shared_ptr<grpc::Channel>> result;
    for (std::size_t i = 0; i != options_.connection_pool_size(); ++i) {
      result.emplace_back(CreateChannel(i));
    }
    return result;
  }

  void ReplaceChannel(std::size_t idx, std::shared_ptr<grpc::Channel> channel) {
    std::unique_lock<std::mutex> lk(mu_);
    stubs_[idx] = Interface::NewStub(channel);
    channels_[idx] = std::move(channel);
  }

  /// Get the current index for round-robin over connections.
  std::size_t GetIndex() {
    std::size_t current = current_index_++;
    // Round robin through the connections.
    if (current_index_ >= stubs_.size()) {
      current_index_ = 0;
    }
    return current;
  }

  std::mutex mu_;
  ClientOptions options_;
  google::cloud::internal::DefaultPRNG rng_;
  std::vector<ChannelPtr> channels_;
  std::vector<StubPtr> stubs_;
  std::size_t current_index_;
  std::unique_ptr<BackgroundThreads> background_threads_;
};

}  // namespace internal
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_BIGTABLE_INTERNAL_COMMON_CLIENT_H
