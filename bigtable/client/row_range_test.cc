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

#include "bigtable/client/row_range.h"

#include <gmock/gmock.h>

namespace btproto = ::google::bigtable::v2;

TEST(RowRangeTest, InfiniteRange) {
  auto proto = bigtable::RowRange::InfiniteRange().as_proto();
  EXPECT_EQ(btproto::RowRange::START_KEY_NOT_SET, proto.start_key_case());
  EXPECT_EQ(btproto::RowRange::END_KEY_NOT_SET, proto.end_key_case());
}

TEST(RowRangeTest, StartingAt) {
  auto proto = bigtable::RowRange::StartingAt("foo").as_proto();
  EXPECT_EQ(btproto::RowRange::kStartKeyClosed, proto.start_key_case());
  EXPECT_EQ("foo", proto.start_key_closed());
  EXPECT_EQ(btproto::RowRange::END_KEY_NOT_SET, proto.end_key_case());
}

TEST(RowRangeTest, EndingAt) {
  auto proto = bigtable::RowRange::EndingAt("foo").as_proto();
  EXPECT_EQ(btproto::RowRange::START_KEY_NOT_SET, proto.start_key_case());
  EXPECT_EQ(btproto::RowRange::kEndKeyClosed, proto.end_key_case());
  EXPECT_EQ("foo", proto.end_key_closed());
}

TEST(RowRangeTest, Range) {
  auto proto = bigtable::RowRange::Range("bar", "foo").as_proto();
  EXPECT_EQ(btproto::RowRange::kStartKeyClosed, proto.start_key_case());
  EXPECT_EQ("bar", proto.start_key_closed());
  EXPECT_EQ(btproto::RowRange::kEndKeyOpen, proto.end_key_case());
  EXPECT_EQ("foo", proto.end_key_open());
}

TEST(RowRangeTest, Prefix) {
  auto proto = bigtable::RowRange::Prefix("bar/baz/").as_proto();
  EXPECT_EQ(btproto::RowRange::kStartKeyClosed, proto.start_key_case());
  EXPECT_EQ("bar/baz/", proto.start_key_closed());
  EXPECT_EQ(btproto::RowRange::kEndKeyOpen, proto.end_key_case());
  EXPECT_EQ("bar/baz0", proto.end_key_open());
}

TEST(RowRangeTest, RightOpen) {
  auto proto = bigtable::RowRange::RightOpen("bar", "foo").as_proto();
  EXPECT_EQ(btproto::RowRange::kStartKeyClosed, proto.start_key_case());
  EXPECT_EQ("bar", proto.start_key_closed());
  EXPECT_EQ(btproto::RowRange::kEndKeyOpen, proto.end_key_case());
  EXPECT_EQ("foo", proto.end_key_open());
}

TEST(RowRangeTest, LeftOpen) {
  auto proto = bigtable::RowRange::LeftOpen("bar", "foo").as_proto();
  EXPECT_EQ(btproto::RowRange::kStartKeyOpen, proto.start_key_case());
  EXPECT_EQ("bar", proto.start_key_open());
  EXPECT_EQ(btproto::RowRange::kEndKeyClosed, proto.end_key_case());
  EXPECT_EQ("foo", proto.end_key_closed());
}

TEST(RowRangeTest, Open) {
  auto proto = bigtable::RowRange::Open("bar", "foo").as_proto();
  EXPECT_EQ(btproto::RowRange::kStartKeyOpen, proto.start_key_case());
  EXPECT_EQ("bar", proto.start_key_open());
  EXPECT_EQ(btproto::RowRange::kEndKeyOpen, proto.end_key_case());
  EXPECT_EQ("foo", proto.end_key_open());
}

TEST(RowRangeTest, Closed) {
  auto proto = bigtable::RowRange::Closed("bar", "foo").as_proto();
  EXPECT_EQ(btproto::RowRange::kStartKeyClosed, proto.start_key_case());
  EXPECT_EQ("bar", proto.start_key_closed());
  EXPECT_EQ(btproto::RowRange::kEndKeyClosed, proto.end_key_case());
  EXPECT_EQ("foo", proto.end_key_closed());
}

TEST(RowRangeTest, IsEmpty) {
  EXPECT_TRUE(bigtable::RowRange::Empty().IsEmpty());
  EXPECT_FALSE(bigtable::RowRange::InfiniteRange().IsEmpty());
  EXPECT_FALSE(bigtable::RowRange::StartingAt("bar").IsEmpty());
  EXPECT_FALSE(bigtable::RowRange::Range("bar", "foo").IsEmpty());
  EXPECT_TRUE(bigtable::RowRange::Range("foo", "foo").IsEmpty());
  EXPECT_TRUE(bigtable::RowRange::Range("foo", "bar").IsEmpty());
  EXPECT_FALSE(bigtable::RowRange::StartingAt("").IsEmpty());
  EXPECT_FALSE(
      bigtable::RowRange::RightOpen("", std::string("\0", 1)).IsEmpty());
}

TEST(RowRangeTest, ContainsRightOpen) {
  auto range = bigtable::RowRange::RightOpen("bar", "foo");
  EXPECT_FALSE(range.Contains("baq"));
  EXPECT_TRUE(range.Contains("bar"));
  EXPECT_FALSE(range.Contains("foo"));
  EXPECT_FALSE(range.Contains("fop"));
  EXPECT_TRUE(range.Contains("bar-foo"));
}

TEST(RowRangeTest, ContainsLeftOpen) {
  auto range = bigtable::RowRange::LeftOpen("bar", "foo");
  EXPECT_FALSE(range.Contains("baq"));
  EXPECT_FALSE(range.Contains("bar"));
  EXPECT_TRUE(range.Contains("foo"));
  EXPECT_FALSE(range.Contains("fop"));
  EXPECT_TRUE(range.Contains("bar-foo"));
}

TEST(RowRangeTest, ContainsOpen) {
  auto range = bigtable::RowRange::Open("bar", "foo");
  EXPECT_FALSE(range.Contains("baq"));
  EXPECT_FALSE(range.Contains("bar"));
  EXPECT_FALSE(range.Contains("foo"));
  EXPECT_FALSE(range.Contains("fop"));
  EXPECT_TRUE(range.Contains("bar-foo"));
}

TEST(RowRangeTest, ContainsClosed) {
  auto range = bigtable::RowRange::Closed("bar", "foo");
  EXPECT_FALSE(range.Contains("baq"));
  EXPECT_TRUE(range.Contains("bar"));
  EXPECT_TRUE(range.Contains("foo"));
  EXPECT_FALSE(range.Contains("fop"));
  EXPECT_TRUE(range.Contains("bar-foo"));
}

TEST(RowRangeTest, ContainsPrefix) {
  auto range = bigtable::RowRange::Prefix("foo");
  EXPECT_FALSE(range.Contains("fop"));
  EXPECT_TRUE(range.Contains("foo"));
  EXPECT_TRUE(range.Contains("foo-bar"));
  EXPECT_TRUE(range.Contains("fooa"));
  EXPECT_TRUE(range.Contains("foo\xFF"));
  EXPECT_FALSE(range.Contains("fop"));
}

TEST(RowRangeTest, ContainsPrefixWithFFFF) {
  std::string many_ffs("\xFF\xFF\xFF\xFF\xFF", 5);
  auto range = bigtable::RowRange::Prefix(many_ffs);
  EXPECT_FALSE(range.Contains(std::string("\xFF\xFF\xFF\xFF\xFE", 5)));
  EXPECT_TRUE(range.Contains(std::string("\xFF\xFF\xFF\xFF\xFF", 5)));
  EXPECT_TRUE(range.Contains(std::string("\xFF\xFF\xFF\xFF\xFF/")));
  EXPECT_TRUE(range.Contains(std::string("\xFF\xFF\xFF\xFF\xFF/foo/bar/baz")));
  EXPECT_FALSE(range.Contains(std::string("\x00\x00\x00\x00\x00\x01", 6)));
}

TEST(RowRangeTest, ContainsStartingAt) {
  auto range = bigtable::RowRange::StartingAt("foo");
  EXPECT_FALSE(range.Contains(""));
  EXPECT_FALSE(range.Contains("fon"));
  EXPECT_TRUE(range.Contains("foo"));
  EXPECT_TRUE(range.Contains("fop"));
}

TEST(RowRangeTest, ContainsEndingAt) {
  auto range = bigtable::RowRange::EndingAt("foo");
  EXPECT_TRUE(range.Contains(""));
  EXPECT_TRUE(range.Contains(std::string("\x01", 1)));
  EXPECT_TRUE(range.Contains("foo"));
  EXPECT_FALSE(range.Contains("fop"));
}

TEST(RowRangeTest, StreamingRightOpen) {
  std::ostringstream os;
  os << bigtable::RowRange::RightOpen("a", "b");
  EXPECT_EQ("['a', 'b')", os.str());
}

TEST(RowRangeTest, StreamingLeftOpen) {
  std::ostringstream os;
  os << bigtable::RowRange::LeftOpen("a", "b");
  EXPECT_EQ("('a', 'b']", os.str());
}

TEST(RowRangeTest, StreamingClosed) {
  std::ostringstream os;
  os << bigtable::RowRange::Closed("a", "b");
  EXPECT_EQ("['a', 'b']", os.str());
}

TEST(RowRangeTest, StreamingOpen) {
  std::ostringstream os;
  os << bigtable::RowRange::Open("a", "b");
  EXPECT_EQ("('a', 'b')", os.str());
}

TEST(RowRangeTest, StreamingStartingAt) {
  std::ostringstream os;
  os << bigtable::RowRange::StartingAt("a");
  EXPECT_EQ("['a', '')", os.str());
}

TEST(RowRangeTest, StreamingEndingAt) {
  std::ostringstream os;
  os << bigtable::RowRange::EndingAt("a");
  EXPECT_EQ("['', 'a']", os.str());
}

TEST(RowRangeTest, EqualsRightOpen) {
  using R = bigtable::RowRange;
  EXPECT_EQ(R::RightOpen("a", "d"), R::RightOpen("a", "d"));
  EXPECT_NE(R::RightOpen("a", "d"), R::RightOpen("a", "c"));
  EXPECT_NE(R::RightOpen("a", "d"), R::RightOpen("b", "d"));
  EXPECT_NE(R::RightOpen("a", "d"), R::LeftOpen("a", "d"));
  EXPECT_NE(R::RightOpen("a", "d"), R::Closed("a", "d"));
  EXPECT_NE(R::RightOpen("a", "d"), R::Open("a", "d"));
}

TEST(RowRangeTest, EqualsLeftOpen) {
  using R = bigtable::RowRange;
  EXPECT_EQ(R::LeftOpen("a", "d"), R::LeftOpen("a", "d"));
  EXPECT_NE(R::LeftOpen("a", "d"), R::LeftOpen("a", "c"));
  EXPECT_NE(R::LeftOpen("a", "d"), R::LeftOpen("b", "d"));
  EXPECT_NE(R::LeftOpen("a", "d"), R::RightOpen("a", "d"));
  EXPECT_NE(R::LeftOpen("a", "d"), R::Closed("a", "d"));
  EXPECT_NE(R::LeftOpen("a", "d"), R::Open("a", "d"));
}

TEST(RowRangeTest, EqualsClosed) {
  using R = bigtable::RowRange;
  EXPECT_EQ(R::Closed("a", "d"), R::Closed("a", "d"));
  EXPECT_NE(R::Closed("a", "d"), R::Closed("a", "c"));
  EXPECT_NE(R::Closed("a", "d"), R::Closed("b", "d"));
  EXPECT_NE(R::Closed("a", "d"), R::RightOpen("a", "d"));
  EXPECT_NE(R::Closed("a", "d"), R::LeftOpen("a", "d"));
  EXPECT_NE(R::Closed("a", "d"), R::Open("a", "d"));
}

TEST(RowRangeTest, EqualsOpen) {
  using R = bigtable::RowRange;
  EXPECT_EQ(R::Open("a", "d"), R::Open("a", "d"));
  EXPECT_NE(R::Open("a", "d"), R::Open("a", "c"));
  EXPECT_NE(R::Open("a", "d"), R::Open("b", "d"));
  EXPECT_NE(R::Open("a", "d"), R::RightOpen("a", "d"));
  EXPECT_NE(R::Open("a", "d"), R::LeftOpen("a", "d"));
  EXPECT_NE(R::Open("a", "d"), R::Closed("a", "d"));
}

TEST(RowRangeTest, EqualsStartingAt) {
  using R = bigtable::RowRange;
  EXPECT_EQ(R::StartingAt("a"), R::StartingAt("a"));
  EXPECT_NE(R::StartingAt("a"), R::StartingAt("b"));
  EXPECT_NE(R::StartingAt("a"), R::RightOpen("a", "d"));
  EXPECT_NE(R::StartingAt("a"), R::LeftOpen("a", "d"));
  EXPECT_NE(R::StartingAt("a"), R::Open("a", "d"));
  EXPECT_NE(R::StartingAt("a"), R::Closed("a", "d"));
}

TEST(RowRangeTest, EqualsEndingAt) {
  using R = bigtable::RowRange;
  EXPECT_EQ(R::EndingAt("b"), R::EndingAt("b"));
  EXPECT_NE(R::EndingAt("b"), R::EndingAt("a"));
  EXPECT_NE(R::EndingAt("b"), R::RightOpen("a", "b"));
  EXPECT_NE(R::EndingAt("b"), R::LeftOpen("a", "b"));
  EXPECT_NE(R::EndingAt("b"), R::Open("a", "b"));
  EXPECT_NE(R::EndingAt("b"), R::Closed("a", "b"));
}

// This is a fairly exhausting (and maybe exhaustive) set of cases for
// intersecting a RightOpen range against other ranges.
using R = bigtable::RowRange;

TEST(RowRangeTest, InterserctRightOpen_Empty) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::Empty());
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_CompletelyBelow) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::RightOpen("a", "b"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_MatchingBoundariesBelow) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::RightOpen("a", "c"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_CompletelyAbove) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::RightOpen("n", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_MatchingBoundariesAbove) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::RightOpen("m", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_StartBelowEndInside) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::RightOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_StartBelowEndInsideClosed) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::LeftOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_CompletelyInsideRightOpen) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::RightOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_CompletelyInsideLeftOpen) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::LeftOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_CompletelyInsideOpen) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::Open("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_CompletelyInsideClosed) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::Closed("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_StartInsideEndAbove) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::RightOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("k", "m"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctRightOpen_StartInsideEndAboveOpen) {
  auto tuple = R::RightOpen("c", "m").Intersect(R::LeftOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("k", "m"), std::get<1>(tuple));
}

// The cases for a LeftOpen interval.
TEST(RowRangeTest, InterserctLeftOpen_Empty) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::Empty());
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_CompletelyBelow) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::RightOpen("a", "b"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_MatchingBoundariesBelow) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::RightOpen("a", "c"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_CompletelyAbove) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::RightOpen("n", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_MatchingBoundariesAbove) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::LeftOpen("m", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_StartBelowEndInside) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::RightOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_StartBelowEndInsideClosed) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::LeftOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_CompletelyInsideRightOpen) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::RightOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_CompletelyInsideLeftOpen) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::LeftOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_CompletelyInsideOpen) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::Open("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_CompletelyInsideClosed) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::Closed("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_StartInsideEndAbove) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::RightOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("k", "m"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctLeftOpen_StartInsideEndAboveOpen) {
  auto tuple = R::LeftOpen("c", "m").Intersect(R::LeftOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("k", "m"), std::get<1>(tuple));
}

// The cases for a Open interval.
TEST(RowRangeTest, IntersectOpen_Empty) {
  auto tuple = R::Open("c", "m").Intersect(R::Empty());
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectOpen_CompletelyBelow) {
  auto tuple = R::Open("c", "m").Intersect(R::RightOpen("a", "b"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectOpen_MatchingBoundariesBelow) {
  auto tuple = R::Open("c", "m").Intersect(R::RightOpen("a", "c"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectOpen_CompletelyAbove) {
  auto tuple = R::Open("c", "m").Intersect(R::RightOpen("n", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectOpen_MatchingBoundariesAbove) {
  auto tuple = R::Open("c", "m").Intersect(R::RightOpen("m", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectOpen_StartBelowEndInside) {
  auto tuple = R::Open("c", "m").Intersect(R::RightOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectOpen_StartBelowEndInsideClosed) {
  auto tuple = R::Open("c", "m").Intersect(R::LeftOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectOpen_CompletelyInsideRightOpen) {
  auto tuple = R::Open("c", "m").Intersect(R::RightOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectOpen_CompletelyInsideLeftOpen) {
  auto tuple = R::Open("c", "m").Intersect(R::LeftOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectOpen_CompletelyInsideOpen) {
  auto tuple = R::Open("c", "m").Intersect(R::Open("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectOpen_CompletelyInsideClosed) {
  auto tuple = R::Open("c", "m").Intersect(R::Closed("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectOpen_StartInsideEndAbove) {
  auto tuple = R::Open("c", "m").Intersect(R::RightOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("k", "m"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectOpen_StartInsideEndAboveOpen) {
  auto tuple = R::Open("c", "m").Intersect(R::LeftOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("k", "m"), std::get<1>(tuple));
}

// The cases for a Closed interval.
TEST(RowRangeTest, IntersectClosed_Empty) {
  auto tuple = R::Closed("c", "m").Intersect(R::Empty());
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectClosed_CompletelyBelow) {
  auto tuple = R::Closed("c", "m").Intersect(R::RightOpen("a", "b"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectClosed_MatchingBoundariesBelow) {
  auto tuple = R::Closed("c", "m").Intersect(R::RightOpen("a", "c"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectClosed_CompletelyAbove) {
  auto tuple = R::Closed("c", "m").Intersect(R::RightOpen("n", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectClosed_MatchingBoundariesAbove) {
  auto tuple = R::Closed("c", "m").Intersect(R::LeftOpen("m", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectClosed_StartBelowEndInside) {
  auto tuple = R::Closed("c", "m").Intersect(R::RightOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectClosed_StartBelowEndInsideClosed) {
  auto tuple = R::Closed("c", "m").Intersect(R::LeftOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectClosed_CompletelyInsideRightOpen) {
  auto tuple = R::Closed("c", "m").Intersect(R::RightOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectClosed_CompletelyInsideLeftOpen) {
  auto tuple = R::Closed("c", "m").Intersect(R::LeftOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectClosed_CompletelyInsideOpen) {
  auto tuple = R::Closed("c", "m").Intersect(R::Open("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectClosed_CompletelyInsideClosed) {
  auto tuple = R::Closed("c", "m").Intersect(R::Closed("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectClosed_StartInsideEndAbove) {
  auto tuple = R::Closed("c", "m").Intersect(R::RightOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("k", "m"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectClosed_StartInsideEndAboveOpen) {
  auto tuple = R::Closed("c", "m").Intersect(R::LeftOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("k", "m"), std::get<1>(tuple));
}

// The cases for a StartingAt interval.
TEST(RowRangeTest, InterserctStartingAt_Empty) {
  auto tuple = R::StartingAt("c").Intersect(R::Empty());
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_CompletelyBelow) {
  auto tuple = R::StartingAt("c").Intersect(R::RightOpen("a", "b"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_MatchingBoundariesBelow) {
  auto tuple = R::StartingAt("c").Intersect(R::RightOpen("a", "c"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_StartBelowEndInside) {
  auto tuple = R::StartingAt("c").Intersect(R::RightOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_StartBelowEndInsideClosed) {
  auto tuple = R::StartingAt("c").Intersect(R::LeftOpen("a", "d"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("c", "d"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_CompletelyInsideRightOpen) {
  auto tuple = R::StartingAt("c").Intersect(R::RightOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_CompletelyInsideLeftOpen) {
  auto tuple = R::StartingAt("c").Intersect(R::LeftOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_CompletelyInsideOpen) {
  auto tuple = R::StartingAt("c").Intersect(R::Open("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_CompletelyInsideClosed) {
  auto tuple = R::StartingAt("c").Intersect(R::Closed("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_StartInsideEndAbove) {
  auto tuple = R::StartingAt("c").Intersect(R::StartingAt("k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::StartingAt("k"), std::get<1>(tuple));
}

TEST(RowRangeTest, InterserctStartingAt_StartInsideEndAboveOpen) {
  auto tuple = R::StartingAt("c").Intersect(R::LeftOpen("k", ""));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("k", ""), std::get<1>(tuple));
}

// The cases for a EndingAt interval.
TEST(RowRangeTest, IntersectEndingAt_Empty) {
  auto tuple = R::EndingAt("m").Intersect(R::Empty());
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_CompletelyAbove) {
  auto tuple = R::EndingAt("m").Intersect(R::RightOpen("n", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_MatchingBoundariesAbove) {
  auto tuple = R::EndingAt("m").Intersect(R::LeftOpen("m", "q"));
  EXPECT_FALSE(std::get<0>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_CompletelyInsideRightOpen) {
  auto tuple = R::EndingAt("m").Intersect(R::RightOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::RightOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_CompletelyInsideLeftOpen) {
  auto tuple = R::EndingAt("m").Intersect(R::LeftOpen("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_CompletelyInsideOpen) {
  auto tuple = R::EndingAt("m").Intersect(R::Open("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Open("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_CompletelyInsideClosed) {
  auto tuple = R::EndingAt("m").Intersect(R::Closed("d", "k"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("d", "k"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_StartInsideEndAbove) {
  auto tuple = R::EndingAt("m").Intersect(R::RightOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::Closed("k", "m"), std::get<1>(tuple));
}

TEST(RowRangeTest, IntersectEndingAt_StartInsideEndAboveOpen) {
  auto tuple = R::EndingAt("m").Intersect(R::LeftOpen("k", "z"));
  EXPECT_TRUE(std::get<0>(tuple));
  EXPECT_EQ(R::LeftOpen("k", "m"), std::get<1>(tuple));
}
