// Copyright 2021 Google LLC
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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_OPTIONS_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_OPTIONS_H

#include "google/cloud/version.h"
#include "absl/types/any.h"
#include <set>
#include <type_traits>
#include <typeindex>
#include <typeinfo>
#include <unordered_map>

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {

class Options;
namespace internal {
// See https://en.cppreference.com/w/cpp/types/type_identity
template <typename T>
struct type_identity {
  using type = T;
};
template <typename T>
using type_identity_t = typename type_identity<T>::type;


template <typename T>
struct value_type {
  using type = decltype(std::declval<T>().value);
};
template <typename T>
using value_type_t = typename value_type<T>::type;

void CheckExpectedOptionsImpl(std::set<std::type_index> const&, Options const&,
                              char const*);
}  // namespace internal

namespace internal {

/**
 * A class that holds option structs indexed by their type.
 *
 * An "Option" can be any unique struct, but by convention these structs tend
 * to have a single data member named "value" and a name like "FooOption".
 * Each library (e.g., spanner, storage) may define their own set of options.
 * Additionally, various common classes may define options. All these options
 * may be set in a single `Options` instance, and each library will look at the
 * options that it needs.
 *
 * @par Example:
 *
 * @code
 * // Given
 * struct EndpointOption {
 *   std::string value;
 * };
 * struct FooOption {
 *   int value;
 * };
 * struct BarOption {
 *   double value;
 * };
 * ...
 * auto opts = Options{}
 *                 .set<EndpointOption>("blah.googleapis.com")
 *                 .set<FooOption>(42);
 * absl::optional<FooOption> foo = opts.get<FooOption>();
 * assert(foo.has_value());
 * assert(foo->value == 42);
 *
 * BarOption bar = opts.get_or<BarOption>(3.14);
 * assert(bar.value == 3.14);
 * @endcode
 */
class Options {
 public:
  /// Constructs an empty instance.
  Options() = default;

  Options(Options const&) = default;
  Options& operator=(Options const&) = default;
  Options(Options&&) = default;
  Options& operator=(Options&&) = default;

  /**
   * Sets the specified option and returns a reference to `*this`.
   *
   * The optional arguments to `set(...)` will be used to construct the `T`
   * option.
   */
  template <typename T>
  Options& set(value_type_t<T> v) {
    T t;
    t.value = std::move(v);
    m_[typeid(T)] = std::move(t);
    return *this;
  }
  template <typename T>
  Options& set(type_identity_t<T> t = {}) {
    return set<T>(std::move(t.value));
  }

  template <typename T>
  bool has() {
    return m_.find(typeid(T)) != m_.end();
  }

  /**
   * Erases the option specified by the type `T`.
   */
  template <typename T>
  void unset() {
    m_.erase(typeid(T));
  }

  /**
   * Gets the option of type `T` if set, else a newly constructed default `T`.
   *
   * If the specified option `T` is not set, a new `T` will be constructed with
   * the optional arguments @p u.
   */
  template <typename T>
  value_type_t<T> get_or(value_type_t<T> default_value) const {
    auto it = m_.find(typeid(T));
    if (it != m_.end()) return absl::any_cast<T>(it->second).value;
    return std::move(default_value);
  }

  template <typename T>
  value_type_t<T> get_or(type_identity_t<T> t = {}) const {
    return get_or<T>(std::move(t.value));
  }

  /**
   * Returns value for the option of type `T` or inserts a new one w/ the given
   * default value.
   */
  template <typename T>
  value_type_t<T>& lookup(value_type_t<T> init_value) {
    auto it = m_.find(typeid(T));
    if (it != m_.end()) return absl::any_cast<T>(&it->second)->value;
    set<T>(std::move(init_value));
    return lookup<T>();  // Recursive call, but the value exists now.
  }

  template <typename T>
  value_type_t<T>& lookup(type_identity_t<T> t = {}) {
    return lookup<T>(std::move(t.value));
  }

 private:
  friend void CheckExpectedOptionsImpl(std::set<std::type_index> const&,
                                       Options const&, char const*);

  std::unordered_map<std::type_index, absl::any> m_;
};

}  // namespace internal

namespace internal {

// Wraps `T` in a `std::tuple`, unless it was already a tuple.
template <typename T>
struct FlatTuple {
  using Type = std::tuple<T>;
};
template <typename... T>
struct FlatTuple<std::tuple<T...>> {
  using Type = std::tuple<T...>;  // Note: Doesn't work w/ nested tuples.
};

template <typename... T>
void CheckExpectedOptionsImpl(std::tuple<T...> const&, Options const& opts,
                              char const* caller) {
  CheckExpectedOptionsImpl({typeid(T)...}, opts, caller);
}

// Checks that `Options` only contains the given expected options or a subset
// of them. Logs all unexpected options. Note that logging is not always shown
// on the console. Set the environment variable
// `GOOGLE_CLOUD_CPP_ENABLE_CLOG=yes` to enable logging.
//
// Options may be specified directly or as a collection within a `std::tuple`.
// For example,
//
// @code
// struct FooOption { int value; };
// struct BarOption { int value; };
// using OptionTuple = std::tuple<FooOption, BarOption>;
//
// struct BazOption { int value; };
//
// // All valid ways to call this with varying expectations.
// CheckExpectedOptions<FooOption>(opts, "test caller");
// CheckExpectedOptions<FooOption, BarOption>(opts, "test caller");
// CheckExpectedOptions<OptionTuple>(opts, "test caller");
// CheckExpectedOptions<BazOption, OptionTuple>(opts, "test caller");
// @endcode
//
// @param opts the `Options` to check.
// @param caller some string indicating the callee function; logged IFF there's
//        an unexpected option
template <typename... T>
void CheckExpectedOptions(Options const& opts, char const* caller) {
  using Tuple = decltype(std::tuple_cat(typename FlatTuple<T>::Type{}...));
  CheckExpectedOptionsImpl(Tuple{}, opts, caller);
}

}  // namespace internal

}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_OPTIONS_H
