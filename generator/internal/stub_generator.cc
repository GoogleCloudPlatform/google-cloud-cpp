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

#include "generator/internal/stub_generator.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/strings/strip.h"
#include "generator/internal/codegen_utils.h"
#include "generator/internal/printer.h"
#include <google/api/client.pb.h>
#include <google/protobuf/descriptor.h>

namespace google {
namespace cloud {
namespace generator_internal {

StubGenerator::StubGenerator(
    google::protobuf::ServiceDescriptor const* service_descriptor,
    std::map<std::string, std::string> service_vars,
    google::protobuf::compiler::GeneratorContext* context)
    : service_descriptor_(service_descriptor),
      vars_(std::move(service_vars)),
      header_(context, vars_["stub_header_path"]),
      cc_(context, vars_["stub_cc_path"]) {
  SetVars();
}

Status StubGenerator::GenerateHeader() {
  // Temporary conditional for unit testing purposes.
  if (service_descriptor_->name() == "FailureService") {
    return Status(StatusCode::kInternal, "Failed for testing.");
  }

  header_.Print(vars_,  // clang-format off
    "// Generated by the Codegen C++ plugin.\n"
    "// If you make any local changes, they will be lost.\n"
    "// source: $proto_file_name$\n"
    "#ifndef $stub_header_include_guard$\n"
    "#define $stub_header_include_guard$\n"
    "\n");
  // clang-format on

  // includes
  header_.Print(LocalInclude("google/cloud/backoff_policy.h"));
  header_.Print(LocalInclude("google/cloud/connection_options.h"));
  header_.Print(LocalInclude("google/cloud/internal/retry_policy.h"));
  header_.Print(LocalInclude("google/cloud/polling_policy.h"));
  header_.Print(LocalInclude("google/cloud/status_or.h"));
  header_.Print(LocalInclude("grpcpp/security/credentials.h"));
  header_.Print(SystemInclude(absl::StrCat(
      absl::StripSuffix(service_descriptor_->file()->name(), ".proto"),
      ".grpc.pb.h")));
  header_.Print(SystemInclude("memory"));
  header_.Print("\n");

  // namespace openers
  auto namespaces = BuildNamespaces(vars_, NamespaceType::kInternal).value();
  for (auto const& nspace : namespaces) {
    if (absl::EndsWith(nspace, "_CLIENT_NS")) {
      header_.Print("inline namespace $namespace$ {\n", "namespace", nspace);
    } else {
      header_.Print("namespace $namespace$ {\n", "namespace", nspace);
    }
  }
  header_.Print("\n");

  // Abstract interface Stub base class
  header_.Print(vars_,  // clang-format off
    "class $stub_class_name$ {\n"
    " public:\n"
    "  virtual ~$stub_class_name$() = 0;\n"
    "\n");
  // clang-format on

  // long running operation support methods
  header_.Print(
      vars_,  // clang-format off
    "  /// Poll a long-running operation.\n"
    "  virtual StatusOr<google::longrunning::Operation> GetOperation(\n"
    "      grpc::ClientContext& client_context,\n"
    "      google::longrunning::GetOperationRequest const& request) = 0;\n"
    "\n"
    "  /// Cancel a long-running operation.\n"
    "  virtual Status CancelOperation(\n"
    "      grpc::ClientContext& client_context,\n"
    "      google::longrunning::CancelOperationRequest const& request) = 0;\n"
    "\n");
  // clang-format on

  // close abstract interface Stub base class
  header_.Print(vars_,  // clang-format off
    "};  // $stub_class_name$\n"
    "\n");
  // clang-format on

  // namespace closers
  std::reverse(namespaces.begin(), namespaces.end());
  for (auto const& nspace : namespaces) {
    header_.Print("}  // namespace $namespace$\n", "namespace", nspace);
  }
  header_.Print("\n");

  // close header guard
  header_.Print(vars_,  // clang-format off
      "#endif  // $stub_header_include_guard$\n");
  // clang-format on
  return {};
}

Status StubGenerator::Generate() { return GenerateHeader(); }

void StubGenerator::SetVars() {
  vars_["stub_header_include_guard"] =
      absl::StrCat("GOOGLE_CLOUD_CPP_",
                   absl::AsciiStrToUpper(absl::StrReplaceAll(
                       vars_["stub_header_path"], {{"/", "_"}, {".", "_"}})));
}

}  // namespace generator_internal
}  // namespace cloud
}  // namespace google
