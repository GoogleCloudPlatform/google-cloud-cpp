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

// Extracts the type of `T`'s `.value` data member.
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
 * An "Option" struct is any struct that has a public `.value` data member. By
 * convention they are named like "FooOption". Each library (e.g., spanner,
 * storage) may define their own set of options. Additionally, there may be
 * common options defined that many libraries may use. All these options may be
 * set in a single `Options` instance, and each library will look at the
 * options that it needs.
 *
 * Here's an overview of this class's interface, but see the method
 * documentation below for details.
 *
 * - `.set<T>(x)`    -- Sets the option `T` to value `x`
 * - `.has<T>()`     -- Returns true iff option `T` is set
 * - `.unset<T>()`   -- Removes the option `T`
 * - `.get_or<T>(x)` -- Gets the value of option `T`, or `x` if no value was set
 * - `.lookup<T>(x)` -- Gets a reference to option `T`'s value, initializing it
 *                      to `x` if it was no set.
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
 * int foo = opts.get_or<FooOption>(123);
 * assert(foo == 42);
 *
 * double bar = opts.get_or<BarOption>(3.14);
 * assert(bar == 3.14);
 *
 * // Modifies the stored EndpointOption's value via a reference
 * std::string& endpoint = opts.lookup<EndpointOption>();
 * endpoint = "new.googleapis.com";
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
   * @code
   * struct FooOption {
   *   int value;
   * };
   * auto opts = Options{}.set<FooOption>(123);
   * @endcode
   *
   * @tparam T the option type
   * @param v the value to set the option T
   */
  template <typename T>
  Options& set(value_type_t<T> v) {
    T t;
    t.value = std::move(v);
    m_[typeid(T)] = std::move(t);
    return *this;
  }

  /**
   * Sets the specified option and returns a reference to `*this`.
   *
   * If the argument @p t is unspecified, the value will be value-initialized.
   *
   * @code
   * struct FooOption {
   *   int value;
   * };
   * FooOption default_foo = {123};
   * auto opts = Options{}.set<FooOption>(default_foo);
   * @endcode
   *
   * @tparam T the option type
   * @param t an instance of `T` to set the option to
   */
  template <typename T>
  Options& set(type_identity_t<T> t = {}) {
    return set<T>(std::move(t.value));
  }

  /**
   * Returns true IFF an option with type `T` exists.
   *
   * @tparam T the option type
   */
  template <typename T>
  bool has() {
    return m_.find(typeid(T)) != m_.end();
  }

  /**
   * Erases the option specified by the type `T`.
   *
   * @tparam T the option type
   */
  template <typename T>
  void unset() {
    m_.erase(typeid(T));
  }

  /**
   * Returns the value for the option of type `T`, else returns the @p
   * default_value.
   *
   * @code
   * struct FooOption {
   *   int value;
   * };
   * Options opts;
   * int x = opts.get_or<FooOption>(123);
   * assert(x == 123);
   *
   * opts.set<FooOption>(42);
   * x = opts.get_or<FooOption>(123);
   * assert(x == 42);
   * @endcode
   *
   * @tparam T the option type
   * @param default_value the value to return if `T` is not set
   */
  template <typename T>
  value_type_t<T> get_or(value_type_t<T> default_value) const {
    auto it = m_.find(typeid(T));
    if (it != m_.end()) return absl::any_cast<T>(it->second).value;
    return default_value;
  }

  /**
   * Returns the value for the option of type `T`, else returns the @p t.value.
   *
   * If unspecified, the @p t argument will be value-initialized.
   *
   * @code
   * struct FooOption {
   *   int value;
   * };
   * FooOption default_foo = {123};
   * Options opts;
   * int x = opts.get_or<FooOption>(default_foo);
   * assert(x == 123);
   *
   * x = opts.get_or<FooOption>();
   * assert(x == 0);  // Value-initialized FooOption::value
   *
   * opts.set<FooOption>(42);
   * x = opts.get_or<FooOption>(123);
   * assert(x == 42);
   * @endcode
   *
   * @tparam T the option type
   * @param default_value the value to return if `T` is not set
   */
  template <typename T>
  value_type_t<T> get_or(type_identity_t<T> t = {}) const {
    return get_or<T>(std::move(t.value));
  }

  /**
   * Returns a reference to the value for the option of type `T`, setting the
   * value to @p init_value if necessary.
   *
   * @code
   * struct BigOption {
   *   std::set<std::string> value;
   * };
   * Options opts;
   * std::set<std::string>& x = opts.lookup<BigOption>();
   * assert(x.empty());
   *
   * x.insert("foo");
   * opts.lookup<BigOption>().insert("bar");
   * assert(x.size() == 2);
   * @endcode
   *
   * @tparam T the option type
   * @param init_value the value to return if `T` is not set
   */
  template <typename T>
  value_type_t<T>& lookup(value_type_t<T> init_value) {
    auto it = m_.find(typeid(T));
    if (it != m_.end()) return absl::any_cast<T>(&it->second)->value;
    set<T>(std::move(init_value));
    return lookup<T>();  // Recursive call, but the value exists now.
  }

  /**
   * Returns a reference to the value for the option of type `T`, setting the
   * value to @p t.init_value if necessary.
   *
   * @code
   * struct BigOption {
   *   std::set<std::string> value;
   * };
   *
   * BigOption default_option = {
   *   set::set<std::string>{"foo", "bar"}
   * };
   *
   * Options opts;
   * std::set<std::string>& x = opts.lookup<BigOption>(default_option);
   * assert(x.size() == 2);
   *
   * x.insert("baz");
   * assert(opts.lookup<BigOption>.size() == 3);
   * @endcode
   *
   * @tparam T the option type
   * @param t the option with the `.value` to use by default
   */
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
