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

#ifndef GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_ROW_RANGE_H_
#define GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_ROW_RANGE_H_

#include "bigtable/client/version.h"

#include <google/bigtable/v2/data.pb.h>

#include <absl/strings/string_view.h>

#include <chrono>

#include "bigtable/client/internal/conjunction.h"

namespace bigtable {
inline namespace BIGTABLE_CLIENT_NS {

class RowRange {
 public:
  RowRange(RowRange&& rhs) noexcept = default;
  RowRange& operator=(RowRange&& rhs) noexcept = default;
  RowRange(RowRange const& rhs) = default;
  RowRange& operator=(RowRange const& rhs) = default;

  /// Return the infinite range, i.e., a range including all possible keys.
  static RowRange InfiniteRange() {
    RowRange tmp;
    return tmp;
  }

  /// Return the range starting at @p begin (included), with no upper limit.
  static RowRange StartingAt(std::string begin) {
    RowRange tmp;
    tmp.row_range_.set_start_key_closed(std::move(begin));
    return tmp;
  }

  /// Return the range ending at @p end (included), with no lower limit.
  static RowRange EndingAt(std::string end) {
    RowRange tmp;
    tmp.row_range_.set_end_key_closed(std::move(end));
    return tmp;
  }

  /// Return an empty range
  static RowRange Empty() {
    RowRange tmp;
    tmp.row_range_.set_start_key_open("");
    tmp.row_range_.set_end_key_open("");
    return tmp;
  }

  /// Return the range representing the interval [@p begin, @p end).
  static RowRange Range(std::string begin, std::string end) {
    return RightOpen(std::move(begin), std::move(end));
  }

  //@{
  /// @name Less common, yet sometimes useful, ranges.
  /// Return a range representing the interval [@p begin, @p end).
  static RowRange RightOpen(std::string begin, std::string end) {
    RowRange tmp;
    if (not begin.empty()) {
      tmp.row_range_.set_start_key_closed(std::move(begin));
    }
    if (not end.empty()) {
      tmp.row_range_.set_end_key_open(std::move(end));
    }
    return tmp;
  }

  /// Return a range representing the interval (@p begin, @p end].
  static RowRange LeftOpen(std::string begin, std::string end) {
    RowRange tmp;
    if (not begin.empty()) {
      tmp.row_range_.set_start_key_open(std::move(begin));
    }
    if (not end.empty()) {
      tmp.row_range_.set_end_key_closed(std::move(end));
    }
    return tmp;
  }

  /// Return a range representing the interval (@p begin, @p end).
  static RowRange Open(std::string begin, std::string end) {
    RowRange tmp;
    if (not begin.empty()) {
      tmp.row_range_.set_start_key_open(std::move(begin));
    }
    if (not end.empty()) {
      tmp.row_range_.set_end_key_open(std::move(end));
    }
    return tmp;
  }

  /// Return a range representing the interval [@p begin, @p end].
  static RowRange Closed(std::string begin, std::string end) {
    RowRange tmp;
    if (not begin.empty()) {
      tmp.row_range_.set_start_key_closed(std::move(begin));
    }
    if (not end.empty()) {
      tmp.row_range_.set_end_key_closed(std::move(end));
    }
    return tmp;
  }
  //@}

  /// Return true if the range is empty, i.e., no valid key will match it.
  bool IsEmpty() const;

  /// Return true if @p key is in the range
  bool Contains(absl::string_view key) const;

  /// Return the filter expression as a protobuf.
  ::google::bigtable::v2::RowRange as_proto() const { return row_range_; }

  /// Move out the underlying protobuf value.
  ::google::bigtable::v2::RowRange as_proto_move() {
    return std::move(row_range_);
  }

 private:
  /// Private to avoid mistaken creation of unitialized ranges.
  RowRange() {}

  /// Return true if @p key is below the start.
  bool BelowStart(absl::string_view key) const;

  /// Return true if @p key is above the end.
  bool AboveEnd(absl::string_view key) const;

 private:
  ::google::bigtable::v2::RowRange row_range_;
};
}  // namespace BIGTABLE_CLIENT_NS
}  // namespace bigtable

#endif  // GOOGLE_CLOUD_CPP_BIGTABLE_CLIENT_ROW_RANGE_H_
