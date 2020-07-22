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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_SPANNER_TIMESTAMP_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_SPANNER_TIMESTAMP_H

#include "google/cloud/spanner/version.h"
#include "google/cloud/status_or.h"
#include "absl/time/time.h"
#include <google/protobuf/timestamp.pb.h>
#include <chrono>
#include <cstdint>
#include <limits>
#include <ostream>
#include <string>
#include <tuple>

namespace google {
namespace cloud {
namespace spanner {
inline namespace SPANNER_CLIENT_NS {

class Timestamp;  // defined below

/**
 * Convenience alias. `std::chrono::sys_time` since C++20.
 */
template <typename Duration>
using sys_time = std::chrono::time_point<std::chrono::system_clock, Duration>;

namespace internal {

// Internal forward declarations to befriend.
StatusOr<Timestamp> TimestampFromRFC3339(std::string const&);
std::string TimestampToRFC3339(Timestamp);
Timestamp TimestampFromProto(protobuf::Timestamp const&);
protobuf::Timestamp TimestampToProto(Timestamp);

}  // namespace internal

/**
 * A representation of the Spanner TIMESTAMP type: An instant in time.
 *
 * A `Timestamp` represents an absolute point in time (i.e., is independent of
 * any time zone), with at least nanosecond precision, and with a range of
 * 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999999Z inclusive.
 *
 * The `MakeTimestamp(src)` factory function(s) should be used to construct
 * `Timestamp` values from standard representations of absolute time.
 *
 * A `Timestamp` can be converted back to a standard representation using
 * `ts.get<T>()`.
 */
class Timestamp {
 public:
  /// Default construction yields 1970-01-01T00:00:00Z.
  Timestamp() : Timestamp(absl::UnixEpoch()) {}

  /// @name Regular value type, supporting copy, assign, move.
  ///@{
  Timestamp(Timestamp&&) = default;
  Timestamp& operator=(Timestamp&&) = default;
  Timestamp(Timestamp const&) = default;
  Timestamp& operator=(Timestamp const&) = default;
  ///@}

  /// @name Relational operators
  ///@{
  friend bool operator==(Timestamp const& a, Timestamp const& b) {
    return a.t_ == b.t_;
  }
  friend bool operator!=(Timestamp const& a, Timestamp const& b) {
    return !(a == b);
  }
  friend bool operator<(Timestamp const& a, Timestamp const& b) {
    return a.t_ < b.t_;
  }
  friend bool operator<=(Timestamp const& a, Timestamp const& b) {
    return !(b < a);
  }
  friend bool operator>=(Timestamp const& a, Timestamp const& b) {
    return !(a < b);
  }
  friend bool operator>(Timestamp const& a, Timestamp const& b) {
    return b < a;
  }
  ///@}

  /// @name Output streaming
  friend std::ostream& operator<<(std::ostream& os, Timestamp ts) {
    return os << ts.ToRFC3339();
  }

  /**
   * Convert the `Timestamp` to the user-specified template type. Fails if
   * `*this` cannot be represented as a `T`.
   *
   * Supported destination types are:
   *   - `google::cloud::spanner::sys_time<Duration>` (`Duration::rep` may
   *      not be wider than `std::intmax_t`.)
   *
   * @par Example
   *
   * @code
   *  sys_time<std::chrono::nanoseconds> tp = ...;
   *  Timestamp ts = MakeTimestamp(tp).value();
   *  assert(tp == ts.get<sys_time<std::chrono::nanoseconds>>().value());
   * @endcode
   */
  template <typename T>
  StatusOr<T> get() const {
    return ConvertTo(T{});
  }

 private:
  template <typename Duration>
  friend StatusOr<Timestamp> MakeTimestamp(sys_time<Duration> const&);

  friend StatusOr<Timestamp> internal::TimestampFromRFC3339(std::string const&);
  friend std::string internal::TimestampToRFC3339(Timestamp);
  friend Timestamp internal::TimestampFromProto(protobuf::Timestamp const&);
  friend protobuf::Timestamp internal::TimestampToProto(Timestamp);

  explicit Timestamp(absl::Time t) : t_(t) {}

  // Conversion from/to RFC3339 string.
  static StatusOr<Timestamp> FromRFC3339(std::string const&);
  std::string ToRFC3339() const;

  // Conversion from/to `protobuf::Timestamp`. These conversions never fail,
  // but may accept/produce protobufs outside their documented range.
  static Timestamp FromProto(protobuf::Timestamp const&);
  protobuf::Timestamp ToProto() const;

  // Helpers for `std::chrono::time_point` conversions.
  template <typename Duration>
  static sys_time<Duration> UnixEpoch() {
    return std::chrono::time_point_cast<Duration>(
        sys_time<Duration>::clock::from_time_t(0));
  }
  static StatusOr<Timestamp> FromRatio(std::intmax_t count,
                                       std::intmax_t numerator,
                                       std::intmax_t denominator);
  StatusOr<std::intmax_t> ToRatio(std::intmax_t min, std::intmax_t max,
                                  std::intmax_t numerator,
                                  std::intmax_t denominator) const;

  // Conversion to a `std::chrono::time_point` on the system clock. May
  // produce out-of-range errors, depending on the properties of `Duration`
  // and the `std::chrono::system_clock` epoch.
  template <typename Duration>
  StatusOr<sys_time<Duration>> ConvertTo(sys_time<Duration> const&) const {
    auto s = ToRatio(std::numeric_limits<typename Duration::rep>::min(),
                     std::numeric_limits<typename Duration::rep>::max(),
                     Duration::period::num, Duration::period::den);
    if (!s) return std::move(s).status();
    return Timestamp::UnixEpoch<Duration>() +
           Duration(static_cast<typename Duration::rep>(*s));
  }

  absl::Time t_;
};

/**
 * Construct a `Timestamp` from a `std::chrono::time_point` on the system
 * clock. May produce out-of-range errors, depending on the properties of
 * `Duration` and the `std::chrono::system_clock` epoch. `Duration::rep` may
 * not be wider than `std::intmax_t`.
 */
template <typename Duration>
StatusOr<Timestamp> MakeTimestamp(sys_time<Duration> const& tp) {
  return Timestamp::FromRatio((tp - Timestamp::UnixEpoch<Duration>()).count(),
                              Duration::period::num, Duration::period::den);
}

/**
 * A sentinel type used to update a commit timestamp column.
 *
 * @see https://cloud.google.com/spanner/docs/commit-timestamp
 */
struct CommitTimestamp {
  friend bool operator==(CommitTimestamp, CommitTimestamp) { return true; }
  friend bool operator!=(CommitTimestamp, CommitTimestamp) { return false; }
};

}  // namespace SPANNER_CLIENT_NS
}  // namespace spanner
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_SPANNER_TIMESTAMP_H
