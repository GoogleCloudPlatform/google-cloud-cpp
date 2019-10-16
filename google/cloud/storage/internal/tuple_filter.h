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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_TUPLE_FILTER_H_
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_TUPLE_FILTER_H_

#include "google/cloud/internal/disjunction.h"
#include "google/cloud/internal/invoke_result.h"
#include "google/cloud/internal/tuple.h"
#include "google/cloud/internal/utility.h"
#include "google/cloud/storage/version.h"
#include <tuple>
#include <type_traits>
#include <utility>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {

/**
 * A helper class to filter a single element from a tuple.
 *
 * Depending on whether to filter the element of not, appropriate tuple type is
 * generate and a "filtering" member function, which either returns an empty
 * tuple or a tuple containing the argument.
 *
 * @tparam T of the filtered element
 * @tparam Filter whether to filter the element.
 */
template <typename T, bool Filter>
struct TupleFilterItem {};

/**
 * Implementation of TupleFilterItem - true branch.
 */
template <typename T>
struct TupleFilterItem<T, true> {
  using Result = std::tuple<T>;
  Result operator()(T&& t) const { return Result(std::forward<T>(t)); }
};

/**
 * Implementation of TupleFilterItem - false branch.
 */
template <typename T>
struct TupleFilterItem<T, false> {
  using Result = std::tuple<>;
  Result operator()(T&&) const { return Result(); }
};

/**
 * A helper to compute the return type of `StaticTupleFilter`.
 *
 * @tparam TPred a type predicate telling if an element stays or is filtered out
 * @tparam Tuple the type of the tuple to filter elements from
 */
template <template <class> class TPred, typename Tuple>
struct FilteredTupleReturnType {};

/**
 * Implementation of FilteredTupleReturnType - recursive case.
 *
 * @tparam TPred a type predicate telling if an element stays or is filtered out
 * @tparam Head the type of the first tuple's element
 * @tparam Tail the remaining types tuple's elements
 */
template <template <class> class TPred, typename Head, typename... Tail>
struct FilteredTupleReturnType<TPred, std::tuple<Head, Tail...>> {
  using Result = typename std::conditional<
      TPred<Head>::value,
      typename google::cloud::internal::invoke_result<
          decltype(std::tuple_cat<std::tuple<Head>,
                                  typename FilteredTupleReturnType<
                                      TPred, std::tuple<Tail...>>::Result>),
          std::tuple<Head>,
          typename FilteredTupleReturnType<TPred,
                                           std::tuple<Tail...>>::Result>::type,
      typename FilteredTupleReturnType<TPred,
                                       std::tuple<Tail...>>::Result>::type;
};

/**
 * Implementation of FilteredTupleReturnType - recursion end / empty tuple.
 *
 * @tparam TPred a type predicate telling if an element stays or is filtered out
 */
template <template <class> class TPred>
struct FilteredTupleReturnType<TPred, std::tuple<>> {
  using Result = std::tuple<>;
};

/**
 * Filter elements from a tuple based on their type.
 *
 * A new tuple is returned with only the elements whose type satisfied the
 * provided type predicate.
 *
 * @tparam TPred a type predicate telling if an element stays or is filtered out
 * @tparam Args the type of the tuple's elements
 *
 * @param tuple the tuple to filter elements from
 */
template <template <class> class TPred, typename... Args>
typename FilteredTupleReturnType<TPred, std::tuple<Args...>>::Result
StaticTupleFilter(std::tuple<Args...> t) {
  return std::tuple_cat(google::cloud::internal::apply(
      [](Args&&... args) {
        return std::tuple_cat(TupleFilterItem<Args, TPred<Args>::value>()(
            std::forward<Args>(args))...);
      },
      std::forward<std::tuple<Args...>>(t)));
}

/**
 * A factory of template predicates checking for lack of presence on a type list
 *
 * @tparam Types the list of types which for which the predicate returns false.
 */
template <typename... Types>
struct NotAmong {
  template <typename T>
  using TPred = std::integral_constant<
      bool, !google::cloud::internal::disjunction<
                std::is_same<typename std::decay<T>::type, Types>...>::value>;
};

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_STORAGE_INTERNAL_TUPLE_FILTER_H_
