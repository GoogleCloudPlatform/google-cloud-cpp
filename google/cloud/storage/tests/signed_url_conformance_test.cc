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

#include "google/cloud/internal/make_unique.h"
#include "google/cloud/storage/client.h"
#include "google/cloud/storage/internal/nljson.h"
#include "google/cloud/storage/internal/signed_url_requests.h"
#include "google/cloud/storage/list_objects_reader.h"
#include "google/cloud/storage/testing/storage_integration_test.h"
#include "google/cloud/terminate_handler.h"
#include "google/cloud/testing_util/assert_ok.h"
#include "google/cloud/testing_util/init_google_mock.h"
#include <gmock/gmock.h>
#include <fstream>
#include <type_traits>

/**
 * @file
 *
 * Executes V4 signed URLs conformance tests described in an external file.
 *
 * We have a common set of conformance tests for V4 signed URLs used in all the
 * GCS client libraries. The tests are stored in an external JSON file. This
 * program receives the file name as an input parameter, loads it, and executes
 * the tests described in the file.
 *
 * A separate command-line argument is the name of a (invalidated) service
 * account key file used to create the signed URLs.
 */

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace {
using ::testing::HasSubstr;

// Initialized in main() below.
char const* account_file_name;
std::map<std::string, internal::nl::json>* tests;

class V4SignedUrlConformanceTest
    : public google::cloud::storage::testing::StorageIntegrationTest,
      public ::testing::WithParamInterface<std::string> {
 protected:
  std::vector<std::pair<std::string, std::string>> ExtractHeaders(
      internal::nl::json j_obj) {
    return ExtractListOfPairs(std::move(j_obj), "headers");
  }

  std::vector<std::pair<std::string, std::string>> ExtractQueryParams(
      internal::nl::json j_obj) {
    return ExtractListOfPairs(std::move(j_obj), "queryParameters");
  }

 private:
  std::vector<std::pair<std::string, std::string>> ExtractListOfPairs(
      internal::nl::json j_obj, std::string const& field) {
    std::vector<std::pair<std::string, std::string>> res;

    // Check for the keys of the relevant field
    for (auto& x : j_obj[field].items()) {
      // The keys are returned in alphabetical order by nlohmann::json, but
      // the order does not matter when creating signed urls.
      res.emplace_back(x.key(), x.value());
    }
    return res;
  }
};

/**
 * Implementation of FixedSizeTuple.
 *
 * For a given number `N` > 0, and a non-empty list of types T..., this returns
 * a std::tuple with the first type of `T...` repeated `N` times, followed by
 * `T...`.
 *
 * This is effectively a recursion, where `N` indicates how many types are left
 * to be prepended to the accumulator (`T...`).
 *
 * @tparam `N` how many times to prepend the first element of `T...` to the
 *     resulting `std::tuple`'s instantiation type list; it should be a
 *     `std::integral_constant<>` rather than a normal `int` to allow for
 *     specializations (14.5.5)
 * @tparam `Enable` a formal parameter to allow for using `std::enable_if`
 * @tparam `T...` tail of the list of types with which the resulting
 *     `std::tuple` will be instantiated
 */
template <typename N, typename Enable, typename... T>
struct FixedSizeTupleImpl {};

/// Recursive case - prepend a type to `T...` and decrease `N`.
template <std::size_t N, typename T1, typename... T>
struct FixedSizeTupleImpl<std::integral_constant<std::size_t, N>,
                          typename std::enable_if<(N > 1), void>::type, T1,
                          T...> {
  using type =
      typename FixedSizeTupleImpl<std::integral_constant<std::size_t, N - 1>,
                                  void, T1, T1, T...>::type;
};

/// End of recursion - instantiate the `std::tuple`.
template <typename... T>
struct FixedSizeTupleImpl<std::integral_constant<std::size_t, 1>, void, T...> {
  using type = std::tuple<T...>;
};

/// Create a tuple with `N` instances of `T`.
template <std::size_t N, typename T>
struct FixedSizeTuple {
  using type =
      typename FixedSizeTupleImpl<std::integral_constant<std::size_t, N>, void,
                                  T>::type;
};

/**
 * Implementation of `RuntimeTupleRef`.
 *
 * This is effectively a recursion which for a tuple of size `N` generates the
 * following code:
 * ```
 * if (N == n) {
 *   return std::get<N>(t);
 * }
 * if (N - 1 == n) {
 *   return std::get<N>(t);
 * }
 * ....
 * if (0 == n) {
 *   return std::get<N>(t);
 * }
 * Terminate("Index out of range");
 * ```
 *
 * `N` tracks how many more `if`s need to be generated.
 */
template <int N, typename T1, typename... T>
struct RuntimeTupleRefImpl {
  T1& operator()(std::tuple<T1, T...>& t, std::size_t n) const {
    if (N == n) {
      return std::get<N>(t);
    }
    return RuntimeTupleRefImpl<N - 1, T1, T...>()(t, n);
  }
};

/// Implementation of `RuntimeTupleRef` - end of recursion.
template <typename T1, typename... T>
struct RuntimeTupleRefImpl<-1, T1, T...> {
  T1& operator()(std::tuple<T1, T...>& /*t*/, std::size_t /*n*/) const {
    Terminate("Index out of range");
  }
};

/**
 * Return the to n-th `std::tuple` element, where `n` is known only at runtime.
 *
 * @tparam T1 the type of the first element of the `std::tuple`
 * @tparam T the types of the remaining `std::tuple`'s elements
 *
 * @param t the searched tuple
 * @param idx the index of the searched element; if the index is invalid for the
 *     given tuple `Terminate` is called
 * @return reference to element `idx` in tuple `t`
 */
template <typename T1, typename... T>
T1& RuntimeTupleRef(std::tuple<T1, T...>& t, std::size_t idx) {
  return RuntimeTupleRefImpl<std::tuple_size<std::tuple<T1, T...>>::value - 1,
                             T1, T...>()(t, idx);
}

struct CreateV4SignedUrlApplyHelper {
  template <typename... Options>
  StatusOr<std::string> operator()(Options&&... options) {
    return client.CreateV4SignedUrl(std::move(verb), std::move(bucket_name),
                                    std::move(object_name),
                                    std::forward<Options>(options)...);
  }

  Client& client;
  std::string verb;
  std::string bucket_name;
  std::string object_name;
};

TEST_P(V4SignedUrlConformanceTest, V4SignJson) {
  std::string account_file = account_file_name;
  auto creds =
      oauth2::CreateServiceAccountCredentialsFromJsonFilePath(account_file);

  ASSERT_STATUS_OK(creds);
  std::string account_email = creds->get()->AccountEmail();
  Client client(*creds);
  std::string actual_canonical_request;
  std::string actual_string_to_sign;

  auto j_obj = (*tests)[GetParam()];
  std::string const method_name = j_obj["method"];
  std::string const bucket_name = j_obj["bucket"];
  std::string const object_name = j_obj["object"];
  std::string const date = j_obj["timestamp"];
  auto const valid_for =
      std::chrono::seconds(std::stoi(j_obj["expiration"].get<std::string>()));
  std::string const expected = j_obj["expectedUrl"];
  std::string const expected_canonical_request =
      j_obj["expectedCanonicalRequest"];
  std::string const expected_string_to_sign = j_obj["expectedStringToSign"];

  // Extract the headers for each object
  auto headers = ExtractHeaders(j_obj);
  auto params = ExtractQueryParams(j_obj);

  google::cloud::storage::internal::V4SignUrlRequest request(
      method_name, bucket_name, object_name);
  request.set_multiple_options(
      SignedUrlTimestamp(google::cloud::internal::ParseRfc3339(date)),
      SignedUrlDuration(valid_for),
      AddExtensionHeader("host", "storage.googleapis.com"));

  FixedSizeTuple<5, AddExtensionHeaderOption>::type header_extensions;
  ASSERT_LE(headers.size(),
            std::tuple_size<decltype(header_extensions)>::value);
  for (std::size_t i = 0; i < headers.size(); ++i) {
    auto& header = headers.at(i);
    request.set_multiple_options(
        AddExtensionHeader(header.first, header.second));
    RuntimeTupleRef(header_extensions, i) =
        AddExtensionHeader(header.first, header.second);
  }

  FixedSizeTuple<5, AddQueryParameterOption>::type query_params;
  ASSERT_LE(params.size(), std::tuple_size<decltype(query_params)>::value);
  for (std::size_t i = 0; i < params.size(); ++i) {
    auto& param = params.at(i);
    request.set_multiple_options(
        AddQueryParameterOption(param.first, param.second));
    RuntimeTupleRef(query_params, i) =
        AddQueryParameterOption(param.first, param.second);
  }

  auto actual = google::cloud::internal::apply(
      CreateV4SignedUrlApplyHelper{client, method_name, bucket_name,
                                   object_name},
      std::tuple_cat(
          std::make_tuple(
              SignedUrlTimestamp(google::cloud::internal::ParseRfc3339(date)),
              SignedUrlDuration(valid_for),
              AddExtensionHeader("host", "storage.googleapis.com")),
          header_extensions, query_params));

  actual_string_to_sign = request.StringToSign(account_email);
  actual_canonical_request = request.CanonicalRequest(account_email);

  ASSERT_STATUS_OK(actual);
  EXPECT_THAT(*actual, HasSubstr(bucket_name));
  EXPECT_EQ(expected, *actual);
  EXPECT_EQ(expected_canonical_request, actual_canonical_request);
  EXPECT_EQ(expected_string_to_sign, actual_string_to_sign);
}

INSTANTIATE_TEST_SUITE_P(
    V4SignedUrlConformanceTest, V4SignedUrlConformanceTest,
    ::testing::ValuesIn([] {
      std::vector<std::string> res;
      std::transform(tests->begin(), tests->end(), std::back_inserter(res),
                     [](std::pair<std::string, internal::nl::json> const& p) {
                       return p.first;
                     });
      return res;
    }()));

}  // namespace
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google

int main(int argc, char* argv[]) {
  // Make sure the arguments are valid.
  if (argc != 3) {
    std::string const cmd = argv[0];
    auto last_slash = std::string(argv[0]).find_last_of('/');
    std::cerr << "Usage: " << cmd.substr(last_slash + 1)
              << " <key-file-name> <conformance-tests-json-file-name>\n";
    return 1;
  }

  google::cloud::storage::account_file_name = argv[1];

  std::ifstream ifstr(argv[2]);
  if (!ifstr.is_open()) {
    std::cerr << "Failed to open data file: \"" << argv[2] << "\"\n";
    return 1;
  }

  auto tests_destroyer = google::cloud::internal::make_unique<
      std::map<std::string, google::cloud::storage::internal::nl::json>>();
  google::cloud::storage::tests = tests_destroyer.get();

  // The implementation is not yet completed and these tests still fail, so skip
  // them so far.
  std::set<std::string> nonconformant_tests{
      "HTTPBucketBoundDomainSupport",
      "HTTPSBucketBoundDomainSupport",
      "Headersshouldbetrimmed",
      "ListObjects",
      "POSTPolicyACLmatching",
      "POSTPolicyCacheControlFileHeader",
      "POSTPolicySimple",
      "POSTPolicySuccessWithRedirect",
      "POSTPolicySuccessWithStatus",
      "POSTPolicyWithinContentRange",
      "SignedPayloadInsteadofUNSIGNEDPAYLOAD",
      "Varyexpirationandtimestamp",
      "VirtualHostedStyle"};

  auto json = google::cloud::storage::internal::nl::json::parse(ifstr);
  if (json.is_discarded()) {
    std::cerr << "Failed to parse provided data file\n";
    return 1;
  }

  if (!json.is_object()) {
    std::cerr << "The provided file should contain one JSON object.\n";
    return 1;
  }
  for (auto& json_array : json.items()) {
    if (!json_array.value().is_array()) {
      std::cerr << "Expected an obects' value to be arrays, found: "
                << json_array.value() << ".\n";
      return 1;
    }

    for (auto const& j_obj : json_array.value()) {
      if (!j_obj.is_object()) {
        std::cerr << "Expected an array of objects, got this element in array: "
                  << j_obj << "\n";
        return 1;
      }
      if (j_obj.count("description") != 1) {
        std::cerr << "Expected all tests to have a description\n";
        return 1;
      }
      auto j_descr = j_obj["description"];
      if (!j_descr.is_string()) {
        std::cerr << "Expected description to be a string, got: " << j_descr
                  << "\n";
        return 1;
      }
      std::string name_with_spaces = j_descr;
      std::string name;
      // gtest doesn't allow for anything other than [a-zA-Z]
      std::copy_if(name_with_spaces.begin(), name_with_spaces.end(),
                   back_inserter(name), [](char c) {
                     return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
                   });
      if (nonconformant_tests.find(name) != nonconformant_tests.end()) {
        continue;
      }
      bool inserted =
          google::cloud::storage::tests->emplace(name, j_obj).second;
      if (!inserted) {
        std::cerr << "Duplicate test description: " << name << "\n";
      }
    }
  }
  google::cloud::testing_util::InitGoogleMock(argc, argv);

  return RUN_ALL_TESTS();
}
