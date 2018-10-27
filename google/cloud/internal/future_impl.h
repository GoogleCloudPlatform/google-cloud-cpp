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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_FUTURE_IMPL_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_FUTURE_IMPL_H_
/**
 * @file
 *
 * Define the implementation details for `google::cloud::future<T>`.
 */

#include "google/cloud/internal/port_platform.h"

// C++ futures only make sense when exceptions are enabled.
#if GOOGLE_CLOUD_CPP_HAVE_EXCEPTIONS
#include "google/cloud/internal/future_then_meta.h"
#include "google/cloud/internal/make_unique.h"
#include <condition_variable>
#include <exception>
#include <future>
#include <mutex>

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {
namespace internal {
/**
 * Define an interface to type-erased continuations.
 *
 * Continuations (the parameters to a `.then()` call) can be of arbitrary
 * types: any callable (lambdas, function pointers, `std::function<>`) should be
 * accepted. We want to hold these continuations as type-erased objects, so we
 * can call them without having to know their types.
 *
 * A continuation object will hold both the callable and the state to call it
 * with, the implementation of `.then()` takes care of those details.
 */
class continuation_base {
 public:
  virtual ~continuation_base() = default;

  /// Invoke the continuation.
  virtual void execute() = 0;
};

/**
 * Common base class for all shared state classes.
 *
 * The implementation of the shared state for future<T>, future<R&> and
 * future<void> share a lot of code. This class refactors that code, it
 * represents a shared state of unknown type.
 *
 * @note While most of the invariants for promises and futures are implemented
 *   by this class, not all of them are. Notably, future values can only be
 *   retrieved once, but this is enforced because calling .get() or .then() on a
 *   future invalidates the future for further use. The shared state does not
 *   record that state change.
 */
class future_shared_state_base {
 public:
  future_shared_state_base() : mu_(), cv_(), current_state_(state::not_ready) {}

  /// Return true if the shared state has a value or an exception.
  bool is_ready() const {
    std::unique_lock<std::mutex> lk(mu_);
    return is_ready_unlocked();
  }

  /// Block until is_ready() returns true ...
  void wait() {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [this] { return is_ready_unlocked(); });
  }

  /**
   * Block until `is_ready()` returns true or until @p duration time has
   * elapsed.
   *
   * @param duration the maximum time to wait for `is_ready()`.
   *
   * @tparam Rep a placeholder to match the Rep tparam for @p duration's
   *     type, the semantics of this template parameter are documented in
   *     `std::chrono::duration<>` (in brief, the underlying arithmetic type
   *     used to store the number of ticks), for our purposes it is simply a
   *     formal parameter.
   * @tparam Period a placeholder to match the Period tparam for @p duration's
   *     type, the semantics of this template parameter are documented in
   *     `std::chrono::duration<>` (in brief, the length of the tick in seconds,
   *     expressed as a `std::ratio<>`), for our purposes it is simply a formal
   *     parameter.
   *
   * @return `std::future_status::ready` if the shared state is satisfied.
   *     `std::future_status::deferred` if the shared state is not satisfied and
   *     there is a continuation ready to execute when it is satisfied.
   *     `std::future_status::timeout` otherwise.
   */
  template <typename Rep, typename Period>
  std::future_status wait_for(std::chrono::duration<Rep, Period> duration) {
    std::unique_lock<std::mutex> lk(mu_);
    bool result =
        cv_.wait_for(lk, duration, [this] { return is_ready_unlocked(); });
    if (result) {
      return std::future_status::ready;
    }
    if (continuation_) {
      return std::future_status::deferred;
    }
    return std::future_status::timeout;
  }

  /**
   * Block until is_ready() returns true or until the @p deadline.
   *
   * @param deadline the maximum time to wait.
   *
   * @tparam Clock a placeholder to match the Clock tparam for @p tp's
   *     type, the semantics of this template parameter are documented in
   *     `std::chrono::time_point<>` (in brief, the underlying clock type
   *     associated with the time point), for our purposes it is simply a
   *     formal parameter.
   *
   * @return `std::future_status::ready` if the shared state is satisfied.
   *     `std::future_status::deferred` if the shared state is not satisfied and
   *     there is a continuation ready to execute when it is satisfied.
   *     `std::future_status::timeout` otherwise.
   */
  template <typename Clock>
  std::future_status wait_until(std::chrono::time_point<Clock> deadline) {
    std::unique_lock<std::mutex> lk(mu_);
    if (not lk.owns_lock()) {
      return std::future_status::timeout;
    }
    bool result =
        cv_.wait_until(lk, deadline, [this] { return is_ready_unlocked(); });
    if (result) {
      return std::future_status::ready;
    }
    if (continuation_) {
      return std::future_status::deferred;
    }
    return std::future_status::timeout;
  }

  /// Set the shared state to hold an exception and notify immediately.
  void set_exception(std::exception_ptr ex) {
    std::unique_lock<std::mutex> lk(mu_);
    set_exception(std::move(ex), lk);
    notify_now(lk);
  }

  /**
   * Abandon the shared state.
   *
   * The destructor of `promise<T>` abandons the state. If it is satisfied this
   * has no effect, but otherwise the state is satisfied with an
   * `std::future_error` exception. The error code is
   * `std::future_errc::broken_promise`.
   */
  void abandon() {
    std::unique_lock<std::mutex> lk(mu_);
    if (is_ready_unlocked()) {
      return;
    }
    set_exception(std::make_exception_ptr(
                      std::future_error(std::future_errc::broken_promise)),
                  lk);
    cv_.notify_all();
  }

  void set_continuation(std::unique_ptr<continuation_base> c) {
    std::unique_lock<std::mutex> lk(mu_);
    if (continuation_) {
      throw std::future_error(std::future_errc::future_already_retrieved);
    }
    // If the future is already satisfied, invoke the continuation immediately.
    if (is_ready_unlocked()) {
      // Release the lock before calling the user's code, holding locks during
      // callbacks is a bad practice.
      lk.unlock();
      c->execute();
      return;
    }
    continuation_ = std::move(c);
  }

 protected:
  bool is_ready_unlocked() const { return current_state_ != state::not_ready; }

  /// Satisfy the shared state using an exception.
  void set_exception(std::exception_ptr ex, std::unique_lock<std::mutex>& lk) {
    if (is_ready_unlocked()) {
      throw std::future_error(std::future_errc::promise_already_satisfied);
    }
    exception_ = std::move(ex);
    current_state_ = state::has_exception;
  }

  /// If needed, notify any waiting threads that the shared state is satisfied.
  void notify_now(std::unique_lock<std::mutex>& lk) {
    if (continuation_) {
      // Release the lock before calling the continuation because the
      // continuation will likely call get() to fetch the state of the future.
      lk.unlock();
      continuation_->execute();
      // If there is a continuation there can be no threads blocked on get() or
      // wait() because then() invalidates the future. Therefore we can return
      // without notifying any other threads.
      return;
    }
    cv_.notify_all();
    // Release the lock after the notification because otherwise the threads
    // may lose the state change.
    lk.unlock();
  }

  // My (@coryan) reading of the spec is that calling get_future() on a promise
  // should succeed exactly once, even when used from multiple threads. This
  // requires some kind of flag and synchronization primitive. The obvious
  // question is whether this flag should be in `promise<T>` or part of the
  // shared state. If it is a member of the shared state then it can be a
  // `std::atomic_flag`, which is guaranteed to be lock free and, well, atomic.
  // But an object of type `std::atomic_flag` (or `std::atomic<bool>`) cannot
  // be a member of `promise<T>` because such objects are not MoveConstructible,
  // and `promise<T>` must be. Once could implement this with an `std::mutex` +
  // a bool, but that is more overhead than just a flag here.
  /// Keep track of whether `get_future()` has been called.
  std::atomic_flag retrieved_ = ATOMIC_FLAG_INIT;

  mutable std::mutex mu_;
  std::condition_variable cv_;
  enum class state {
    not_ready,
    has_exception,
    has_value,
  };
  state current_state_;
  std::exception_ptr exception_;

  /**
   * The continuation, if any, associated with this shared state.
   *
   * Note that continuations may be set independently of having a value or
   * exception. Setting a continuation does not change the `current_state_`
   * member variable and does not satisfy the shared state.
   */
  std::unique_ptr<continuation_base> continuation_;
};

/**
 * Forward declare the generic version of future_share_state.
 *
 * TODO(#1345) - implement the generic version
 */
template <typename T>
class future_shared_state;

/**
 * Specialize the shared state for `void`.
 *
 * The shared state for `void` does not have any value to hold, `get()` does
 * not return any value, and `set_value()` does not take any arguments. We must
 * use an specialization because the default implementation would define
 * `set_value()` as `set_value(void&&)` which is not legal, nor is the signature
 * we want for that matter.
 */
template <>
class future_shared_state<void> final : private future_shared_state_base {
 public:
  future_shared_state() : future_shared_state_base() {}

  using future_shared_state_base::abandon;
  using future_shared_state_base::is_ready;
  using future_shared_state_base::set_continuation;
  using future_shared_state_base::set_exception;
  using future_shared_state_base::wait;
  using future_shared_state_base::wait_for;
  using future_shared_state_base::wait_until;

  /// The implementation details for `future<void>::get()`
  void get() {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [this] { return is_ready_unlocked(); });
    if (current_state_ == state::has_exception) {
      std::rethrow_exception(exception_);
    }
  }

  /// The implementation details for `promise<void>::set_value()`
  void set_value() {
    std::unique_lock<std::mutex> lk(mu_);
    set_value(lk);
    notify_now(lk);
  }

  /**
   * Create a continuation object wrapping the given functor.
   *
   * Unlike most member functions in template classes this is defined out of
   * line. We need to do so because:
   *
   * * This function creates a `continuation<void>`.
   * * `continuation<void>` needs to see the full definition of `future<T>`.
   * * Therefore `continuation<T>` cannot be defined before this point.
   *
   * @tparam F the functor type.
   * @param self the object that will hold the continuation.
   * @param functor the continuation type.
   * @return A shared pointer to the shared state that will store the results
   *     of the continuation.
   */
  template <typename F>
  static std::shared_ptr<
      typename internal::continuation_helper<F, void>::state_t>
  make_continuation(std::shared_ptr<future_shared_state> self, F&& functor);

  /**
   * The implementation details for `promise<void>::get_future()`.
   *
   * `promise<void>::get_future()` can be called exactly once, this function
   * must raise `std::future_error` if (quoting the C++ spec):
   *
   * `get_future` has already been called on a `promise` with the same shared
   * state as `*this`
   *
   * While it is not clear how one could create multiple promises pointing to
   * the same shared state, it is easier to keep all the locking and atomic
   * checks in one class.
   *
   * @throws std::future_error if the operation fails.
   */
  static void mark_retrieved(std::shared_ptr<future_shared_state> const& sh) {
    if (not sh) {
      throw std::future_error(std::future_errc::no_state);
    }
    if (sh->retrieved_.test_and_set()) {
      throw std::future_error(std::future_errc::future_already_retrieved);
    }
  }

 private:
  void set_value(std::unique_lock<std::mutex> const& lk) {
    if (is_ready_unlocked()) {
      throw std::future_error(std::future_errc::promise_already_satisfied);
    }
    current_state_ = state::has_value;
  }
};

// TODO(#1345) - implement the generic version when future_shared_state<T> is
// implemented.
template <typename Functor, typename R, typename T>
void continuation_execute_delegate(
    Functor& functor, std::shared_ptr<future_shared_state<T>> input,
    future_shared_state<R>& output, std::true_type requires_unwrap);

// TODO(#1345) - implement the generic version when future_shared_state<T> is
// implemented.
template <typename Functor, typename R, typename T>
void continuation_execute_delegate(
    Functor& functor, std::shared_ptr<future_shared_state<T>> input,
    future_shared_state<R>& output, std::false_type requires_unwrap);

/**
 * Calls a functor passing `future<T>` as an argument and stores the results in
 * a `future_shared_state<void>`.
 *
 * This is an specialization of `continuation_execute_delegate` for `void`
 * results. If the output value of `future<T>::then()` is a `void`, we must call
 * `.set_value()` without parameters. The generic version does not work in that
 * case.
 *
 * @tparam Functor the type of the functor.
 * @param functor the callable to invoke.
 * @param input the input shared state, it must be satisfied when this function
 *     is called.
 * @param output the output shared state, it will become satisfied by passing
 *     the results of calling `functor`
 */
template <typename Functor, typename T>
void continuation_execute_delegate(
    Functor& functor, std::shared_ptr<future_shared_state<T>> input,
    future_shared_state<void>& output, std::false_type) try {
  functor(std::move(input));
  output.set_value();
} catch (std::future_error const& f) {
  // failing to set the output with a future_error is non-recoverable, raise
  // immediately.
  throw;
} catch (...) {
  // Other errors can be reported via the promise.
  output.set_exception(std::current_exception());
}

/**
 * Calls a functor passing `future<T>` as an argument and stores the results in
 * a `future_shared_state<void>`.
 *
 * This is an specialization of `continuation_execute_delegate` for
 * functors that return a `future<void>`. In this case we need to unwrap the
 * result and store its "value" in the output shared state. The generic version
 * does not work in that case.
 *
 * @tparam Functor the type of the functor.
 * @param functor the callable to invoke.
 * @param input the input shared state, it must be satisfied when this function
 *     is called.
 * @param output the output shared state, it will become satisfied by passing
 *     the results of calling `functor`
 *
 * @tparam Functor the type of the functor.
 * @param functor the callable to invoke.
 * @param input the input shared state, it must be satisfied when this function
 *     is called.
 * @param output the output shared state, it will become satisfied by passing
 *     the results of calling `functor`
 *
 * TODO(#1345) - implement this in a future PR.
 */
template <typename Functor, typename T>
void continuation_execute_delegate(
    Functor& functor, std::shared_ptr<future_shared_state<T>> input,
    future_shared_state<void>& output, std::true_type);

/**
 * Implement continuations for `future<R>::then()`.
 *
 * Calling `future<R>::then()` creates a new shared state. When the `future<R>`
 * is satisfied the functor parameter pass to `.then()` is called and the newly
 * created shared state is satisfied with the result of calling the functor.
 *
 * This class holds both the functor to call, and the shared state to store the
 * results of calling said functor.
 *
 * @tparam R the value type for the input future.
 * @tparam Functor the type of the functor parameter, it must meet the
 *   `is_invocable<Functor, future_shared_state<R>>` requirement.
 */
template <typename Functor, typename R>
struct continuation : public continuation_base {
  using result_t = typename continuation_helper<Functor, R>::result_t;
  using input_shared_state_t = future_shared_state<R>;
  using output_shared_state_t = future_shared_state<result_t>;
  using requires_unwrap_t =
      typename continuation_helper<Functor, R>::requires_unwrap_t;

  continuation(Functor&& f, std::shared_ptr<input_shared_state_t> s)
      : functor(std::move(f)),
        input(s),
        output(std::make_shared<future_shared_state<result_t>>()) {}

  void execute() override {
    auto tmp = input.lock();
    if (not tmp) {
      output->set_exception(std::make_exception_ptr(
          std::future_error(std::future_errc::no_state)));
      return;
    }
    // The transfer of the state depends on the types involved, delegate to
    // some helper functions.
    continuation_execute_delegate(functor, std::move(tmp), *output,
                                  requires_unwrap_t{});
    output.reset();
  }

  /// The functor called when `input` is satisfied.
  Functor functor;

  /// The shared state that must be satisfied before calling `functor`.
  std::weak_ptr<input_shared_state_t> input;

  /// The shared state that will hold the results of calling `functor`.
  std::shared_ptr<output_shared_state_t> output;
};

// Implement the helper function to create a shared state for continuations.
template <typename F>
std::shared_ptr<typename internal::continuation_helper<F, void>::state_t>
future_shared_state<void>::make_continuation(
    std::shared_ptr<future_shared_state<void>> self, F&& functor) {
  using continuation_type = internal::continuation<F, void>;
  auto continuation = google::cloud::internal::make_unique<continuation_type>(
      std::forward<F>(functor), self);
  auto result = continuation->output;
  self->set_continuation(
      std::unique_ptr<continuation_base>(std::move(continuation)));
  return result;
}

}  // namespace internal
}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_HAVE_EXCEPTIONS
#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_FUTURE_IMPL_H_
