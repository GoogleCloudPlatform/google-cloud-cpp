// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "generator/internal/connection_generator.h"
#include "absl/memory/memory.h"
#include "generator/internal/codegen_utils.h"
#include "generator/internal/descriptor_utils.h"
#include "generator/internal/predicate_utils.h"
#include "generator/internal/printer.h"
#include <google/api/client.pb.h>
#include <google/protobuf/descriptor.h>

namespace google {
namespace cloud {
namespace generator_internal {

ConnectionGenerator::ConnectionGenerator(
    google::protobuf::ServiceDescriptor const* service_descriptor,
    VarsDictionary service_vars,
    std::map<std::string, VarsDictionary> service_method_vars,
    google::protobuf::compiler::GeneratorContext* context)
    : ServiceCodeGenerator("connection_header_path", "connection_cc_path",
                           service_descriptor, std::move(service_vars),
                           std::move(service_method_vars), context) {}

Status ConnectionGenerator::GenerateHeader() {
  HeaderPrint(CopyrightLicenseFileHeader());
  HeaderPrint(  // clang-format off
    "// Generated by the Codegen C++ plugin.\n"
    "// If you make any local changes, they will be lost.\n"
    "// source: $proto_file_name$\n"
    "#ifndef $header_include_guard$\n"
    "#define $header_include_guard$\n"
    "\n");
  // clang-format on

  // includes
  HeaderLocalIncludes(
      {vars("idempotency_policy_header_path"), vars("stub_header_path"),
       vars("retry_traits_header_path"), "google/cloud/backoff_policy.h",
       HasLongrunningMethod() ? "google/cloud/future.h" : "",
       "google/cloud/options.h",
       HasLongrunningMethod() ? "google/cloud/polling_policy.h" : "",
       "google/cloud/status_or.h",
       HasStreamingReadMethod() || HasPaginatedMethod()
           ? "google/cloud/stream_range.h"
           : "",
       "google/cloud/version.h"});
  HeaderSystemIncludes(
      {HasLongrunningMethod() ? "google/longrunning/operations.grpc.pb.h" : "",
       "memory"});
  HeaderPrint("\n");

  auto result = HeaderOpenNamespaces();
  if (!result.ok()) return result;

  HeaderPrint(  // clang-format off
    "using $retry_policy_name$ = google::cloud::internal::TraitBasedRetryPolicy<\n"
    "    $product_internal_namespace$::$retry_traits_name$>;\n"
    "\n"
    "using $limited_time_retry_policy_name$ = google::cloud::internal::LimitedTimeRetryPolicy<\n"
    "    $product_internal_namespace$::$retry_traits_name$>;\n"
    "\n"
    "using $limited_error_count_retry_policy_name$ =\n"
    "    google::cloud::internal::LimitedErrorCountRetryPolicy<\n"
    "        $product_internal_namespace$::$retry_traits_name$>;\n\n"
    //  clang-format on
  );

  // streaming updater functions
  for (auto const& method : methods()) {
    HeaderPrintMethod(
        method,
        {MethodPattern(
            {// clang-format off
   {"void $service_name$$method_name$StreamingUpdater(\n"
    "    $response_type$ const& response,\n"
    "    $request_type$& request);\n\n"}
     }, IsStreamingRead)},
                // clang-format on
        __FILE__, __LINE__);
  }

  // Abstract interface Connection base class
  HeaderPrint(  // clang-format off
    "class $connection_class_name$ {\n"
    " public:\n"
    "  virtual ~$connection_class_name$() = 0;\n"
    "\n");
  // clang-format on

  for (auto const& method : methods()) {
    HeaderPrintMethod(
        method,
        {MethodPattern(
             {
                 {IsResponseTypeEmpty,
                  // clang-format off
    "  virtual Status\n",
    "  virtual StatusOr<$response_type$>\n"},
   {"  $method_name$($request_type$ const& request);\n"
        "\n",}
                 // clang-format on
             },
             All(IsNonStreaming, Not(IsLongrunningOperation),
                 Not(IsPaginated))),
         MethodPattern(
             {
                 {IsResponseTypeEmpty,
                  // clang-format off
    "  virtual future<Status>\n",
    "  virtual future<StatusOr<$longrunning_deduced_response_type$>>\n"},
   {"  $method_name$($request_type$ const& request);\n"
        "\n",}
                 // clang-format on
             },
             All(IsNonStreaming, IsLongrunningOperation, Not(IsPaginated))),
         MethodPattern(
             {
                 // clang-format off
   {"  virtual StreamRange<$range_output_type$>\n"
    "  $method_name$($request_type$ request);\n\n"},
                 // clang-format on
             },
             All(IsNonStreaming, Not(IsLongrunningOperation), IsPaginated)),
         MethodPattern(
             {
                 // clang-format off
   {"  virtual StreamRange<$response_type$>\n"
    "  $method_name$($request_type$ const& request);\n\n"},
                 // clang-format on
             },
             IsStreamingRead)},
        __FILE__, __LINE__);
  }

  // close abstract interface Connection base class
  HeaderPrint(  // clang-format off
    "};\n\n");
  // clang-format on

  HeaderPrint(  // clang-format off
    "std::shared_ptr<$connection_class_name$> Make$connection_class_name$(\n"
    "    Options options = {});\n\n");
  // clang-format on

  HeaderCloseNamespaces();

  HeaderOpenNamespaces(NamespaceType::kInternal);
  HeaderPrint(
      // clang-format off
      "std::shared_ptr<$product_namespace$::$connection_class_name$>\n"
      "Make$connection_class_name$(\n"
      "    std::shared_ptr<$stub_class_name$> stub,\n"
      "    Options options = {});\n\n");
  // clang-format on
  HeaderCloseNamespaces();

  // close header guard
  HeaderPrint(  // clang-format off
    "#endif  // $header_include_guard$\n");
  // clang-format on
  return {};
}

Status ConnectionGenerator::GenerateCc() {
  CcPrint(CopyrightLicenseFileHeader());
  CcPrint(  // clang-format off
    "// Generated by the Codegen C++ plugin.\n"
    "// If you make any local changes, they will be lost.\n"
    "// source: $proto_file_name$\n\n");
  // clang-format on

  // includes
  CcLocalIncludes(
      {vars("connection_header_path"), vars("options_header_path"),
       vars("option_defaults_header_path"), vars("stub_factory_header_path"),
       HasPaginatedMethod() ? "google/cloud/internal/pagination_range.h" : "",
       HasLongrunningMethod() ? "google/cloud/internal/polling_loop.h" : "",
       HasStreamingReadMethod()
           ? "google/cloud/internal/resumable_streaming_read_rpc.h"
           : "",
       "google/cloud/internal/retry_loop.h",
       HasStreamingReadMethod()
           ? "google/cloud/internal/streaming_read_rpc_logging.h"
           : ""});
  CcSystemIncludes({"memory"});
  CcPrint("\n");

  auto result = CcOpenNamespaces();
  if (!result.ok()) return result;

  CcPrint(  // clang-format off
    "$connection_class_name$::~$connection_class_name$() = default;\n\n");
  // clang-format on

  for (auto const& method : methods()) {
    CcPrintMethod(
        method,
        {MethodPattern(
             {
                 {IsResponseTypeEmpty,
                  // clang-format off
    "Status\n",
    "StatusOr<$response_type$>\n"},
   {"$connection_class_name$::$method_name$(\n"
    "    $request_type$ const&) {\n"
    "  return Status(StatusCode::kUnimplemented, \"not implemented\");\n"
    "}\n\n"
    },
                 // clang-format on
             },
             All(IsNonStreaming, Not(IsLongrunningOperation),
                 Not(IsPaginated))),
         MethodPattern(
             {
                 {IsResponseTypeEmpty,
                  // clang-format off
    "future<Status>\n",
    "future<StatusOr<$longrunning_deduced_response_type$>>\n"},
   {"$connection_class_name$::$method_name$(\n"
    "    $request_type$ const&) {\n"
    "  return google::cloud::make_ready_future<\n"
    "    StatusOr<$longrunning_deduced_response_type$>>(\n"
    "    Status(StatusCode::kUnimplemented, \"not implemented\"));\n"
    "}\n\n"
    },
                 // clang-format on
             },
             All(IsNonStreaming, IsLongrunningOperation, Not(IsPaginated))),
         MethodPattern(
             {
                 // clang-format off
   {"StreamRange<$range_output_type$> $connection_class_name$::$method_name$(\n"
    "    $request_type$ request) {\n"
    "  return google::cloud::internal::MakePaginationRange<StreamRange<\n"
    "    $range_output_type$>>(\n"
    "    std::move(request),\n"
    "    []($request_type$ const&) {\n"
    "      return StatusOr<$response_type$>{};\n"
    "    },\n"
    "    []($response_type$ const&) {\n"
    "      return std::vector<$range_output_type$>();\n"
    "    });\n"
    "}\n\n"
                     // clang-format on
                 },
             },
             All(IsNonStreaming, Not(IsLongrunningOperation), IsPaginated)),
         MethodPattern(
             {
                 // clang-format off
   {"StreamRange<$response_type$> $connection_class_name$::$method_name$(\n"
    "    $request_type$ const&) {\n"
    "  return google::cloud::internal::MakeStreamRange<\n"
    "      $response_type$>(\n"
    "      []() -> absl::variant<Status,\n"
    "      $response_type$>{\n"
    "        return Status(StatusCode::kUnimplemented, \"not implemented\");}\n"
    "      );\n"
    "}\n\n"
                     // clang-format on
                 },
             },
             IsStreamingRead)},
        __FILE__, __LINE__);
  }

  // open anonymous namespace
  CcPrint("namespace {\n");
  // default connection implementation class
  CcPrint(
      {//clang-format off
       {"class $connection_class_name$Impl : public $connection_class_name$ {\n"
        " public:\n"
        "  $connection_class_name$Impl(\n"
        "      "
        "std::shared_ptr<$product_internal_namespace$::$stub_class_name$> "
        "stub,\n"
        "      Options const& options)\n"
        "      : stub_(std::move(stub)),\n"
        "        "
        "retry_policy_prototype_(options.get<$retry_policy_name$Option>()->"
        "clone()),\n"
        "        "
        "backoff_policy_prototype_(options.get<$service_name$"
        "BackoffPolicyOption>()->clone()),\n"},
       {[this] { return HasLongrunningMethod(); },
        "        "
        "polling_policy_prototype_(options.get<$service_name$"
        "PollingPolicyOption>()->clone()),\n",
        ""},
       {"        "
        "idempotency_policy_(options.get<$idempotency_class_name$Option>()->"
        "clone()) {}\n"
        "\n"
        "  ~$connection_class_name$Impl() override = default;\n\n"}});
  //  clang-format on

  for (auto const& method : methods()) {
    CcPrintMethod(
        method,
        {MethodPattern(
             {
                 {IsResponseTypeEmpty,
                  // clang-format off
    "  Status\n",
    "  StatusOr<$response_type$>\n"},
   {"  $method_name$(\n"
    "      $request_type$ const& request) override {\n"
    "    return google::cloud::internal::RetryLoop(\n"
    "        retry_policy_prototype_->clone(), backoff_policy_prototype_->clone(),\n"
    "        idempotency_policy_->$method_name$(request),\n"
    "        [this](grpc::ClientContext& context,\n"
    "            $request_type$ const& request) {\n"
    "          return stub_->$method_name$(context, request);\n"
    "        },\n"
    "        request, __func__);\n"
    "}\n"
    "\n",}
                 // clang-format on
             },
             All(IsNonStreaming, Not(IsLongrunningOperation),
                 Not(IsPaginated))),
         MethodPattern(
             {
                 {IsResponseTypeEmpty,
                  // clang-format off
    "  future<Status>\n",
    "  future<StatusOr<$longrunning_deduced_response_type$>>\n"},
   {"  $method_name$(\n"
    "      $request_type$ const& request) override {\n"
    "    auto operation = google::cloud::internal::RetryLoop(\n"
    "        retry_policy_prototype_->clone(), backoff_policy_prototype_->clone(),\n"
    "        idempotency_policy_->$method_name$(request),\n"
    "        [this](grpc::ClientContext& context,\n"
    "               $request_type$ const& request) {\n"
    "          return stub_->$method_name$(context, request);\n"
    "        },\n"
    "        request, __func__);\n"
    "    if (!operation) {\n"
    "      return google::cloud::make_ready_future(\n"
    "          StatusOr<$longrunning_deduced_response_type$>(operation.status()));\n"
    "    }\n"
    "\n"
    "    return Await$method_name$(*std::move(operation));\n"
    "}\n"
    "\n",}
                 // clang-format on
             },
             All(IsNonStreaming, IsLongrunningOperation, Not(IsPaginated))),
         MethodPattern(
             {
                 // clang-format off
   {"  StreamRange<$range_output_type$> $method_name$(\n"
    "      $request_type$ request) override {\n"
    "    request.clear_page_token();\n"
    "    auto stub = stub_;\n"
    "    auto retry =\n"
    "        std::shared_ptr<$retry_policy_name$ const>(retry_policy_prototype_->clone());\n"
    "    auto backoff = std::shared_ptr<BackoffPolicy const>(\n"
    "        backoff_policy_prototype_->clone());\n"
    "    auto idempotency = idempotency_policy_->$method_name$(request);\n"
    "    char const* function_name = __func__;\n"
    "    return google::cloud::internal::MakePaginationRange<StreamRange<\n"
    "        $range_output_type$>>(\n"
    "        std::move(request),\n"
    "        [stub, retry, backoff, idempotency, function_name]\n"
    "          ($request_type$ const& r) {\n"
    "          return google::cloud::internal::RetryLoop(\n"
    "              retry->clone(), backoff->clone(), idempotency,\n"
    "              [stub](grpc::ClientContext& context,\n"
    "                     $request_type$ const& request) {\n"
    "                return stub->$method_name$(context, request);\n"
    "              },\n"
    "              r, function_name);\n"
    "        },\n"
    "        []($response_type$ r) {\n"
    "          std::vector<$range_output_type$> result(r.$range_output_field_name$().size());\n"
    "          auto& messages = *r.mutable_$range_output_field_name$();\n"
    "          std::move(messages.begin(), messages.end(), result.begin());\n"
    "          return result;\n"
    "        });\n"
    "  }\n\n"
                     // clang-format on
                 },
             },
             All(IsNonStreaming, Not(IsLongrunningOperation), IsPaginated)),
         MethodPattern(
             {
                 // clang-format off
   {"  StreamRange<$response_type$> $method_name$(\n"
    "      $request_type$ const& request) override {\n"
    "    auto stub = stub_;\n"
    "    auto retry_policy =\n"
    "        std::shared_ptr<$retry_policy_name$ const>(\n"
    "            retry_policy_prototype_->clone());\n"
    "    auto backoff_policy = std::shared_ptr<BackoffPolicy const>(\n"
    "        backoff_policy_prototype_->clone());\n"
    "\n"
    "    auto factory = [stub](\n"
    "        $request_type$ const& request) {\n"
    "      return stub->$method_name$(absl::make_unique<grpc::ClientContext>(),\n"
    "          request);\n"
    "    };\n"
    "\n"
    "    auto resumable =\n"
    "        internal::MakeResumableStreamingReadRpc<\n"
    "            $response_type$,\n"
    "            $request_type$>(\n"
    "                retry_policy->clone(), backoff_policy->clone(),\n"
    "                [](std::chrono::milliseconds) {}, factory,\n"
    "                $service_name$$method_name$StreamingUpdater,\n"
    "                request);\n"
    "\n"
    "    return internal::MakeStreamRange(internal::StreamReader<\n"
    "        $response_type$>(\n"
    "        [resumable]{return resumable->Read();}));\n"
    "  }\n\n"
                     // clang-format on
                 },
             },
             IsStreamingRead)},
        __FILE__, __LINE__);
  }

  CcPrint(  // clang-format off
    " private:\n");
  // clang-format on

  if (HasLongrunningMethod()) {
    // TODO(#4038) - use the (implicit) completion queue to run this loop, and
    // once using a completion queue, consider changing to AsyncCancelOperation.
    CcPrint(  // clang-format off
    "  template <typename MethodResponse, template<typename> class Extractor,\n"
    "    typename Stub>\n"
    "  future<StatusOr<MethodResponse>>\n"
    "  AwaitLongrunningOperation(google::longrunning::Operation operation) {  // NOLINT\n"
    "    using ResponseExtractor = Extractor<MethodResponse>;\n"
    "    std::weak_ptr<Stub> cancel_stub(stub_);\n"
    "    promise<typename ResponseExtractor::ReturnType> pr(\n"
    "        [cancel_stub, operation]() {\n"
    "          grpc::ClientContext context;\n"
    "          context.set_deadline(std::chrono::system_clock::now() +\n"
    "            std::chrono::seconds(60));\n"
    "          google::longrunning::CancelOperationRequest request;\n"
    "          request.set_name(operation.name());\n"
    "          if (auto ptr = cancel_stub.lock()) {\n"
    "            ptr->CancelOperation(context, request);\n"
    "          }\n"
    "    });\n"
    "    auto f = pr.get_future();\n"
    "    std::thread t(\n"
    "        [](std::shared_ptr<Stub> stub,\n"
    "           google::longrunning::Operation operation,\n"
    "           std::unique_ptr<PollingPolicy> polling_policy,\n"
    "           google::cloud::promise<typename ResponseExtractor::ReturnType> promise,\n"
    "           char const* location) mutable {\n"
    "          auto result = google::cloud::internal::PollingLoop<ResponseExtractor>(\n"
    "              std::move(polling_policy),\n"
    "              [stub](grpc::ClientContext& context,\n"
    "                     google::longrunning::GetOperationRequest const& request) {\n"
    "                return stub->GetOperation(context, request);\n"
    "              },\n"
    "              std::move(operation), location);\n"
    "          stub.reset();\n"
    "          promise.set_value(std::move(result));\n"
    "        },\n"
    "        stub_, std::move(operation), polling_policy_prototype_->clone(),\n"
    "        std::move(pr), __func__);\n"
    "    t.detach();\n"
    "    return f;\n"
    "  }\n\n"
    );
    // clang-format on
  }

  for (auto const& method : methods()) {
    CcPrintMethod(
        method,
        {MethodPattern(
            {
                {IsResponseTypeEmpty,
                 // clang-format off
    "  future<Status>\n",
    "  future<StatusOr<$longrunning_deduced_response_type$>>\n"},
   {"  Await$method_name$(\n"
    "      google::longrunning::Operation operation) {\n"
    "    return AwaitLongrunningOperation<\n"
    "        $longrunning_deduced_response_type$,\n"},
   {IsLongrunningMetadataTypeUsedAsResponse,
    "        google::cloud::internal::PollingLoopMetadataExtractor,\n",
    "        google::cloud::internal::PollingLoopResponseExtractor,\n"},
   {"        golden_internal::$stub_class_name$>(std::move(operation));\n"
    "  }\n\n"}
                // clang-format on
            },
            All(IsNonStreaming, IsLongrunningOperation, Not(IsPaginated)))},
        __FILE__, __LINE__);
  }

  CcPrint(
      {// clang-format off
   {"  std::shared_ptr<$product_internal_namespace$::$stub_class_name$> stub_;\n"
    "  std::unique_ptr<$retry_policy_name$ const> retry_policy_prototype_;\n"
    "  std::unique_ptr<BackoffPolicy const> backoff_policy_prototype_;\n"},
   {[this]{return HasLongrunningMethod();},
    "  std::unique_ptr<PollingPolicy const> polling_policy_prototype_;\n", ""},
   {"  std::unique_ptr<$idempotency_class_name$> idempotency_policy_;\n"
    "};\n"}});
  // clang-format on

  CcPrint("}  // namespace\n\n");

  CcPrint(  // clang-format off
    "std::shared_ptr<$connection_class_name$> Make$connection_class_name$(\n"
    "    Options options) {\n"
    "  options = $product_internal_namespace$::$service_name$DefaultOptions(\n"
    "      std::move(options));\n"
    "  return std::make_shared<$connection_class_name$Impl>(\n"
    "      $product_internal_namespace$::CreateDefault$stub_class_name$(options), options);\n"
    "}\n\n");
  // clang-format on

  CcCloseNamespaces();
  CcOpenNamespaces(NamespaceType::kInternal);

  CcPrint(  // clang-format off
    "std::shared_ptr<$product_namespace$::$connection_class_name$>\n"
    "Make$connection_class_name$(\n"
    "    std::shared_ptr<$stub_class_name$> stub,\n"
    "    Options options) {\n"
    "  options = $service_name$DefaultOptions(\n"
    "      std::move(options));\n"
    "  return std::make_shared<$product_namespace$::$connection_class_name$Impl>(\n"
    "      std::move(stub), std::move(options));\n"
    "}\n\n");
  // clang-format on

  CcCloseNamespaces();
  return {};
}

}  // namespace generator_internal
}  // namespace cloud
}  // namespace google
