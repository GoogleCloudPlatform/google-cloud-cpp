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

#include "generator/internal/logging_decorator_generator.h"
#include "google/cloud/internal/absl_str_cat_quiet.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_split.h"
#include "generator/internal/codegen_utils.h"
#include "generator/internal/descriptor_utils.h"
#include "generator/internal/predicate_utils.h"
#include "generator/internal/printer.h"
#include <google/api/client.pb.h>
#include <google/protobuf/descriptor.h>

namespace google {
namespace cloud {
namespace generator_internal {

LoggingDecoratorGenerator::LoggingDecoratorGenerator(
    google::protobuf::ServiceDescriptor const* service_descriptor,
    VarsDictionary service_vars,
    std::map<std::string, VarsDictionary> service_method_vars,
    google::protobuf::compiler::GeneratorContext* context)
    : ServiceCodeGenerator("logging_header_path", "logging_cc_path",
                           service_descriptor, std::move(service_vars),
                           std::move(service_method_vars), context) {}

Status LoggingDecoratorGenerator::GenerateHeader() {
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
  HeaderLocalIncludes({vars("stub_header_path"),
                       "google/cloud/tracing_options.h",
                       "google/cloud/version.h"});
  HeaderSystemIncludes(
      {HasLongrunningMethod() ? "google/longrunning/operations.grpc.pb.h" : "",
       "memory", "set", "string"});
  HeaderPrint("\n");

  auto result = HeaderOpenNamespaces(NamespaceType::kInternal);
  if (!result.ok()) return result;

  // Abstract interface Logging base class
  HeaderPrint(  // clang-format off
    "class $logging_class_name$ : public $stub_class_name$ {\n"
    " public:\n"
    "  ~$logging_class_name$() override = default;\n"
    "  $logging_class_name$(std::shared_ptr<$stub_class_name$> child,\n"
    "                       TracingOptions tracing_options,\n"
    "                       std::set<std::string> components);\n"
    "\n");
  // clang-format on

  for (auto const& method : methods()) {
    HeaderPrintMethod(
        method,
        {MethodPattern({{IsResponseTypeEmpty,
                         // clang-format off
    "  Status $method_name$(\n",
    "  StatusOr<$response_type$> $method_name$(\n"},
   {"    grpc::ClientContext& context,\n"
    "    $request_type$ const& request) override;\n"
                         // clang-format on
                         "\n"}},
                       IsNonStreaming),
         MethodPattern(
             {// clang-format off
   {"  std::unique_ptr<internal::StreamingReadRpc<$response_type$>>\n"
    "  $method_name$(\n"
    "    grpc::ClientContext& context,\n"
    "    $request_type$ const& request) override;\n"
               // clang-format on
               "\n"}},
             IsStreamingRead)},
        __FILE__, __LINE__);
  }

  if (HasLongrunningMethod()) {
    HeaderPrint(  // clang-format off
    "  /// Poll a long-running operation.\n"
    "  StatusOr<google::longrunning::Operation> GetOperation(\n"
    "      grpc::ClientContext& context,\n"
    "      google::longrunning::GetOperationRequest const& request) "
    "override;\n"
    "\n"
    "  /// Cancel a long-running operation.\n"
    "  Status CancelOperation(\n"
    "      grpc::ClientContext& context,\n"
    "      google::longrunning::CancelOperationRequest const& request) "
    "override;\n"
    "\n");
    // clang-format on
  }

  HeaderPrint(  // clang-format off
    " private:\n"
    "  std::shared_ptr<$stub_class_name$> child_;\n"
    "  TracingOptions tracing_options_;\n"
    "  std::set<std::string> components_;\n"
    "};  // $logging_class_name$\n"
    "\n");
  // clang-format on

  HeaderCloseNamespaces();
  // close header guard
  HeaderPrint(  // clang-format off
      "#endif  // $header_include_guard$\n");
  // clang-format on
  return {};
}

Status LoggingDecoratorGenerator::GenerateCc() {
  CcPrint(CopyrightLicenseFileHeader());
  CcPrint(  // clang-format off
    "// Generated by the Codegen C++ plugin.\n"
    "// If you make any local changes, they will be lost.\n"
    "// source: $proto_file_name$\n");
  // clang-format on

  // includes
  CcLocalIncludes({vars("logging_header_path"),
                   "google/cloud/internal/log_wrapper.h",
                   HasStreamingReadMethod()
                       ? "google/cloud/internal/streaming_read_rpc_logging.h"
                       : "",
                   "google/cloud/status_or.h"});
  CcSystemIncludes({vars("proto_grpc_header_path"), "memory"});
  CcPrint("\n");

  auto result = CcOpenNamespaces(NamespaceType::kInternal);
  if (!result.ok()) return result;

  // constructor
  CcPrint(  // clang-format off
    "$logging_class_name$::$logging_class_name$(\n"
    "    std::shared_ptr<$stub_class_name$> child,\n"
    "    TracingOptions tracing_options,\n"
    "    std::set<std::string> components)\n"
    "    : child_(std::move(child)), tracing_options_(std::move(tracing_options)),\n"
    "      components_(std::move(components)) {}\n"
    "\n");
  // clang-format on

  // logging decorator class member methods
  for (auto const& method : methods()) {
    CcPrintMethod(
        method,
        {MethodPattern(
             {{IsResponseTypeEmpty,
               // clang-format off
    "Status\n",
    "StatusOr<$response_type$>\n"},
    {
    "$logging_class_name$::$method_name$(\n"
    "    grpc::ClientContext& context,\n"
    "    $request_type$ const& request) {\n"
    "  return google::cloud::internal::LogWrapper(\n"
    "      [this](grpc::ClientContext& context,\n"
    "             $request_type$ const& request) {\n"
    "        return child_->$method_name$(context, request);\n"
    "      },\n"
    "      context, request, __func__, tracing_options_);\n"
    "}\n"
    "\n"}},
             // clang-format on
             IsNonStreaming),
         MethodPattern(
             {// clang-format off}
              {"std::unique_ptr<internal::StreamingReadRpc<$response_type$>>\n"
               "$logging_class_name$::$method_name$(\n"
               "    grpc::ClientContext& context,\n"
               "    $request_type$ const& request) {\n"
               "  return google::cloud::internal::LogWrapper(\n"
               "      [this](grpc::ClientContext& context,\n"
               "             $request_type$ const& request) ->\n"
               "      "
               "std::unique_ptr<internal::StreamingReadRpc<$response_type$>> "
               "{\n"
               "        if (components_.count(\"rpc-streams\") > 0) {\n"
               "          return "
               "absl::make_unique<internal::StreamingReadRpcLogging<\n"
               "             $response_type$>>(\n"
               "             child_->$method_name$(context, request), "
               "tracing_options_, internal::RequestIdForLogging());\n"
               "        }\n"
               "        return child_->$method_name$(context, request);\n"
               "      },\n"
               "      context, request, __func__, tracing_options_);\n"
               "}\n"
               "\n"}},
             // clang-format on
             IsStreamingRead)},
        __FILE__, __LINE__);
  }

  // long running operation support methods
  if (HasLongrunningMethod()) {
    CcPrint(  // clang-format off
    "StatusOr<google::longrunning::Operation> $logging_class_name$::GetOperation(\n"
    "    grpc::ClientContext& context,\n"
    "    google::longrunning::GetOperationRequest const& request) {\n"
    "  return google::cloud::internal::LogWrapper(\n"
    "      [this](grpc::ClientContext& context,\n"
    "             google::longrunning::GetOperationRequest const& request) {\n"
    "        return child_->GetOperation(context, request);\n"
    "      },\n"
    "      context, request, __func__, tracing_options_);\n"
    "}\n"
    "\n"
    "Status $logging_class_name$::CancelOperation(\n"
    "    grpc::ClientContext& context,\n"
    "    google::longrunning::CancelOperationRequest const& request) {\n"
    "  return google::cloud::internal::LogWrapper(\n"
    "      [this](grpc::ClientContext& context,\n"
    "             google::longrunning::CancelOperationRequest const& request) {\n"
    "        return child_->CancelOperation(context, request);\n"
    "      },\n"
    "      context, request, __func__, tracing_options_);\n"
    "}\n"
              // clang-format on
    );
  }

  CcCloseNamespaces();
  return {};
}

}  // namespace generator_internal
}  // namespace cloud
}  // namespace google
