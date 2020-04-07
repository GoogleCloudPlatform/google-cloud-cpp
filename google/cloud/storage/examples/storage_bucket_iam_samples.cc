// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "google/cloud/storage/client.h"
#include "google/cloud/storage/examples/storage_examples_common.h"
#include "google/cloud/internal/getenv.h"
#include <functional>
#include <iostream>

namespace {
using google::cloud::storage::examples::Commands;
using google::cloud::storage::examples::CommandType;
using google::cloud::storage::examples::Usage;

void GetBucketIamPolicy(google::cloud::storage::Client client,
                        std::vector<std::string> const& argv) {
  //! [get bucket iam policy]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name) {
    StatusOr<google::cloud::IamPolicy> policy =
        client.GetBucketIamPolicy(bucket_name);

    if (!policy) throw std::runtime_error(policy.status().message());
    std::cout << "The IAM policy for bucket " << bucket_name << " is "
              << *policy << "\n";
  }
  //! [get bucket iam policy]
  (std::move(client), argv.at(0));
}

void NativeGetBucketIamPolicy(google::cloud::storage::Client client,
                              std::vector<std::string> const& argv) {
  //! [native get bucket iam policy] [START storage_view_bucket_iam_members]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name) {
    auto policy = client.GetNativeBucketIamPolicy(
        bucket_name, gcs::RequestedPolicyVersion(3));

    if (!policy) throw std::runtime_error(policy.status().message());
    std::cout << "The IAM policy for bucket " << bucket_name << " is "
              << *policy << "\n";
  }
  //! [native get bucket iam policy] [END storage_view_bucket_iam_members]
  (std::move(client), argv.at(0));
}

void AddBucketIamMember(google::cloud::storage::Client client,
                        std::vector<std::string> const& argv) {
  //! [add bucket iam member]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name, std::string role,
     std::string member) {
    StatusOr<google::cloud::IamPolicy> policy =
        client.GetBucketIamPolicy(bucket_name);

    if (!policy) throw std::runtime_error(policy.status().message());
    policy->bindings.AddMember(role, member);

    StatusOr<google::cloud::IamPolicy> updated =
        client.SetBucketIamPolicy(bucket_name, *policy);

    if (!updated) throw std::runtime_error(updated.status().message());

    std::cout << "Updated IAM policy bucket " << bucket_name
              << ". The new policy is " << *updated << "\n";
  }
  //! [add bucket iam member]
  (std::move(client), argv.at(0), argv.at(1), argv.at(2));
}

void NativeAddBucketIamMember(google::cloud::storage::Client client,
                              std::vector<std::string> const& argv) {
  //! [native add bucket iam member] [START storage_add_bucket_iam_member]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name, std::string role,
     std::string member) {
    auto policy = client.GetNativeBucketIamPolicy(
        bucket_name, gcs::RequestedPolicyVersion(3));

    if (!policy) throw std::runtime_error(policy.status().message());

    policy->set_version(3);
    for (auto& binding : policy->bindings()) {
      if (binding.role() != role || binding.has_condition()) {
        continue;
      }
      auto& members = binding.members();
      if (std::find(members.begin(), members.end(), member) == members.end()) {
        members.emplace_back(member);
      }
    }

    auto updated = client.SetNativeBucketIamPolicy(bucket_name, *policy);
    if (!updated) throw std::runtime_error(updated.status().message());

    std::cout << "Updated IAM policy bucket " << bucket_name
              << ". The new policy is " << *updated << "\n";
  }
  //! [native add bucket iam member] [END storage_add_bucket_iam_member]
  (std::move(client), argv.at(0), argv.at(1), argv.at(2));
}

void NativeAddBucketConditionalIamBinding(
    google::cloud::storage::Client client,
    std::vector<std::string> const& argv) {
  // [START storage_add_bucket_conditional_iam_binding]
  //! [native add bucket conditional iam binding]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name, std::string role,
     std::string member, std::string condition_title,
     std::string condition_description, std::string condition_expression) {
    auto policy = client.GetNativeBucketIamPolicy(
        bucket_name, gcs::RequestedPolicyVersion(3));
    if (!policy) throw std::runtime_error(policy.status().message());

    policy->set_version(3);
    policy->bindings().emplace_back(gcs::NativeIamBinding(
        role, {member},
        gcs::NativeExpression(condition_expression, condition_title,
                              condition_description)));

    auto updated = client.SetNativeBucketIamPolicy(bucket_name, *policy);
    if (!updated) throw std::runtime_error(updated.status().message());

    std::cout << "Updated IAM policy bucket " << bucket_name
              << ". The new policy is " << *updated << "\n";

    std::cout << "Added member " << member << " with role " << role << " to "
              << bucket_name << ":\n";
    std::cout << "with condition:\n"
              << "\t Title: " << condition_title << "\n"
              << "\t Description: " << condition_description << "\n"
              << "\t Expression: " << condition_expression << "\n";
  }
  //! [native add bucket conditional iam binding]
  // [END storage_add_bucket_conditional_iam_binding]
  (std::move(client), argv.at(0), argv.at(1), argv.at(2), argv.at(3),
   argv.at(4), argv.at(5));
}

void RemoveBucketIamMember(google::cloud::storage::Client client,
                           std::vector<std::string> const& argv) {
  //! [remove bucket iam member]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name, std::string role,
     std::string member) {
    StatusOr<google::cloud::IamPolicy> policy =
        client.GetBucketIamPolicy(bucket_name);
    if (!policy) throw std::runtime_error(policy.status().message());
    policy->bindings.RemoveMember(role, member);

    StatusOr<google::cloud::IamPolicy> updated =
        client.SetBucketIamPolicy(bucket_name, *policy);
    if (!updated) throw std::runtime_error(updated.status().message());

    std::cout << "Updated IAM policy bucket " << bucket_name
              << ". The new policy is " << *updated << "\n";
  }
  //! [remove bucket iam member]
  (std::move(client), argv.at(0), argv.at(1), argv.at(2));
}

void NativeRemoveBucketIamMember(google::cloud::storage::Client client,
                                 std::vector<std::string> const& argv) {
  //! [native remove bucket iam member] [START storage_remove_bucket_iam_member]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name, std::string role,
     std::string member) {
    auto policy = client.GetNativeBucketIamPolicy(
        bucket_name, gcs::RequestedPolicyVersion(3));
    if (!policy) throw std::runtime_error(policy.status().message());

    policy->set_version(3);
    std::vector<google::cloud::storage::NativeIamBinding> updated_bindings;
    for (auto& binding : policy->bindings()) {
      auto& members = binding.members();
      if (binding.role() == role && !binding.has_condition()) {
        members.erase(std::remove(members.begin(), members.end(), member),
                      members.end());
      }
      if (!members.empty()) {
        updated_bindings.emplace_back(std::move(binding));
      }
    }
    policy->bindings() = std::move(updated_bindings);

    auto updated = client.SetNativeBucketIamPolicy(bucket_name, *policy);
    if (!updated) throw std::runtime_error(updated.status().message());

    std::cout << "Updated IAM policy bucket " << bucket_name
              << ". The new policy is " << *updated << "\n";
  }
  //! [native remove bucket iam member] [END storage_remove_bucket_iam_member]
  (std::move(client), argv.at(0), argv.at(1), argv.at(2));
}

void NativeRemoveBucketConditionalIamBinding(
    google::cloud::storage::Client client,
    std::vector<std::string> const& argv) {
  //  [START storage_remove_bucket_conditional_iam_binding]
  //! [native remove bucket conditional iam binding]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name, std::string role,
     std::string condition_title, std::string condition_description,
     std::string condition_expression) {
    auto policy = client.GetNativeBucketIamPolicy(
        bucket_name, gcs::RequestedPolicyVersion(3));
    if (!policy) throw std::runtime_error(policy.status().message());

    policy->set_version(3);
    auto& bindings = policy->bindings();
    auto e = std::remove_if(
        bindings.begin(), bindings.end(),
        [role, condition_title, condition_description,
         condition_expression](gcs::NativeIamBinding b) {
          return (b.role() == role && b.has_condition() &&
                  b.condition().title() == condition_title &&
                  b.condition().description() == condition_description &&
                  b.condition().expression() == condition_expression);
        });
    if (e == bindings.end()) {
      std::cout << "No matching binding group found.\n";
      return;
    }
    bindings.erase(e);
    auto updated = client.SetNativeBucketIamPolicy(bucket_name, *policy);
    if (!updated) throw std::runtime_error(updated.status().message());

    std::cout << "Conditional binding was removed.\n";
  }
  //! [native remove bucket conditional iam binding]
  // [END storage_remove_bucket_conditional_iam_binding]
  (std::move(client), argv.at(0), argv.at(1), argv.at(2), argv.at(3),
   argv.at(4));
}

void TestBucketIamPermissions(std::vector<std::string> argv) {
  if (argv.size() < 2) {
    throw Usage{
        "test-bucket-iam-permissions <bucket_name> <permission>"
        " [permission ...]"};
  }
  auto bucket_name = argv[0];
  argv.erase(argv.begin());
  std::vector<std::string> permissions = std::move(argv);
  auto client = google::cloud::storage::Client::CreateDefaultClient().value();

  //! [test bucket iam permissions]
  namespace gcs = google::cloud::storage;
  using ::google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name,
     std::vector<std::string> permissions) {
    StatusOr<std::vector<std::string>> actual_permissions =
        client.TestBucketIamPermissions(bucket_name, permissions);

    if (!actual_permissions) {
      throw std::runtime_error(actual_permissions.status().message());
    }
    if (actual_permissions->empty()) {
      std::cout << "The caller does not hold any of the tested permissions the"
                << " bucket " << bucket_name << "\n";
      return;
    }

    std::cout << "The caller is authorized for the following permissions on "
              << bucket_name << ": ";
    for (auto const& permission : *actual_permissions) {
      std::cout << "\n    " << permission;
    }
    std::cout << "\n";
  }
  //! [test bucket iam permissions]
  (std::move(client), std::move(bucket_name), std::move(permissions));
}

void SetBucketPublicIam(google::cloud::storage::Client client,
                        std::vector<std::string> const& argv) {
  // [START storage_set_bucket_public_iam]
  namespace gcs = google::cloud::storage;
  using google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name) {
    StatusOr<google::cloud::IamPolicy> current_policy =
        client.GetBucketIamPolicy(bucket_name);

    if (!current_policy) {
      throw std::runtime_error(current_policy.status().message());
    }

    current_policy->bindings.AddMember("roles/storage.objectViewer",
                                       "allUsers");

    // Update the policy. Note the use of `gcs::IfMatchEtag` to implement
    // optimistic concurrency control.
    StatusOr<google::cloud::IamPolicy> updated_policy =
        client.SetBucketIamPolicy(bucket_name, *current_policy,
                                  gcs::IfMatchEtag(current_policy->etag));

    if (!updated_policy) {
      throw std::runtime_error(current_policy.status().message());
    }

    auto role = updated_policy->bindings.find("roles/storage.objectViewer");
    if (role == updated_policy->bindings.end()) {
      std::cout << "Cannot find 'roles/storage.objectViewer' in the updated"
                << " policy. This can happen if another application updates"
                << " the IAM policy at the same time. Please retry the"
                << " operation.\n";
      return;
    }
    auto member = role->second.find("allUsers");
    if (member == role->second.end()) {
      std::cout << "'allUsers' is not a member of the"
                << " 'roles/storage.objectViewer' role in the updated"
                << " policy. This can happen if another application updates"
                << " the IAM policy at the same time. Please retry the"
                << " operation.\n";
      return;
    }
    std::cout << "IamPolicy successfully updated for bucket " << bucket_name
              << '\n';
  }
  // [END storage_set_bucket_public_iam]
  (std::move(client), argv.at(0));
}

void NativeSetBucketPublicIam(google::cloud::storage::Client client,
                              std::vector<std::string> const& argv) {
  // [START native storage_set_bucket_public_iam]
  namespace gcs = google::cloud::storage;
  using google::cloud::StatusOr;
  [](gcs::Client client, std::string bucket_name) {
    auto current_policy = client.GetNativeBucketIamPolicy(
        bucket_name, gcs::RequestedPolicyVersion(3));

    if (!current_policy) {
      throw std::runtime_error(current_policy.status().message());
    }

    current_policy->set_version(3);
    current_policy->bindings().emplace_back(
        gcs::NativeIamBinding("roles/storage.objectViewer", {"allUsers"}));

    auto updated =
        client.SetNativeBucketIamPolicy(bucket_name, *current_policy);
    if (!updated) throw std::runtime_error(updated.status().message());

    std::cout << "Policy successfully updated: " << *updated << "\n";
  }
  // [END native storage_set_bucket_public_iam]
  (std::move(client), argv.at(0));
}

void RunAll(std::vector<std::string> const& argv) {
  namespace examples = ::google::cloud::storage::examples;
  namespace gcs = ::google::cloud::storage;

  if (!argv.empty()) throw Usage{"auto"};
  examples::CheckEnvironmentVariablesAreSet({
      "GOOGLE_CLOUD_PROJECT",
      "GOOGLE_CLOUD_CPP_STORAGE_TEST_SERVICE_ACCOUNT",
  });
  auto const project_id =
      google::cloud::internal::GetEnv("GOOGLE_CLOUD_PROJECT").value_or("");
  auto const service_account =
      google::cloud::internal::GetEnv(
          "GOOGLE_CLOUD_CPP_STORAGE_TEST_SERVICE_ACCOUNT")
          .value_or("");
  auto generator = google::cloud::internal::DefaultPRNG(std::random_device{}());
  auto const bucket_name =
      examples::MakeRandomBucketName(generator, "cloud-cpp-test-examples-");
  auto client = gcs::Client::CreateDefaultClient().value();
  std::cout << "\nCreating bucket to run the examples (" << bucket_name << ")"
            << std::endl;

  auto iam_configuration = [] {
    gcs::UniformBucketLevelAccess ubla;
    ubla.enabled = true;
    gcs::BucketIamConfiguration result;
    result.uniform_bucket_level_access = std::move(ubla);
    return result;
  };
  auto bucket_metadata =
      client
          .CreateBucketForProject(
              bucket_name, project_id,
              gcs::BucketMetadata{}.set_iam_configuration(iam_configuration()))
          .value();

  std::cout << "\nRunning GetBucketIamPolicy() example" << std::endl;
  GetBucketIamPolicy(client, {bucket_name});

  std::cout << "\nRunning AddBucketIamMember() example" << std::endl;
  AddBucketIamMember(client, {bucket_name, "roles/storage.objectViewer",
                              "serviceAccount:" + service_account});

  std::cout << "\nRunning RemoveBucketIamMember() example" << std::endl;
  RemoveBucketIamMember(client, {bucket_name, "roles/storage.objectViewer",
                                 "serviceAccount:" + service_account});

  std::cout << "\nRunning TestBucketIamPermissions() example" << std::endl;
  TestBucketIamPermissions(
      {bucket_name, "storage.objects.list", "storage.objects.delete"});

  std::cout << "\nRunning NativeGetBucketIamPolicy() example" << std::endl;
  NativeGetBucketIamPolicy(client, {bucket_name});

  std::cout << "\nRunning NativeAddBucketIamMember() example" << std::endl;
  NativeAddBucketIamMember(client, {bucket_name, "roles/storage.objectViewer",
                                    "serviceAccount:" + service_account});

  std::cout << "\nRunning NativeRemoveBucketIamMember() example" << std::endl;
  NativeRemoveBucketIamMember(client,
                              {bucket_name, "roles/storage.objectViewer",
                               "serviceAccount:" + service_account});

  std::cout << "\nRunning NativeAddBucketConditionalIamBinding() example"
            << std::endl;
  std::string const condition_title = "A match-prefix conditional IAM";
  std::string const condition_description = "Not a good description";
  std::string const condition_expression =
      R"expr(resource.name.startsWith("projects/_/buckets/bucket-name/objects/prefix-a-"))expr";
  NativeAddBucketConditionalIamBinding(
      client, {bucket_name, "roles/storage.objectViewer",
               "serviceAccount:" + service_account, condition_title,
               condition_description, condition_expression});

  std::cout << "\nRunning NativeRemoveBucketConditionalIamBinding() example [1]"
            << std::endl;
  NativeRemoveBucketConditionalIamBinding(
      client, {bucket_name, "roles/storage.objectViewer", condition_title,
               condition_description, condition_expression});
  std::cout << "\nRunning NativeRemoveBucketConditionalIamBinding() example [2]"
            << std::endl;
  NativeRemoveBucketConditionalIamBinding(
      client, {bucket_name, "roles/storage.objectViewer", condition_title,
               condition_description, condition_expression});

  std::cout << "\nRunning NativeSetBucketPublicIam() example" << std::endl;
  NativeSetBucketPublicIam(client, {bucket_name});

  std::cout << "\nRunning SetBucketPublicIam() example" << std::endl;
  SetBucketPublicIam(client, {bucket_name});

  (void)client.DeleteBucket(bucket_name);
}

}  // anonymous namespace

int main(int argc, char* argv[]) {
  namespace examples = ::google::cloud::storage::examples;
  auto make_entry = [](std::string const& name,
                       std::vector<std::string> arg_names,
                       examples::ClientCommand const& cmd) {
    arg_names.insert(arg_names.begin(), "<bucket-name>");
    return examples::CreateCommandEntry(name, std::move(arg_names), cmd);
  };
  google::cloud::storage::examples::Example example({
      make_entry("get-bucket-iam-policy", {}, GetBucketIamPolicy),
      make_entry("native-get-bucket-iam-policy", {}, NativeGetBucketIamPolicy),
      make_entry("add-bucket-iam-member", {"<role>", "<member>"},
                 AddBucketIamMember),
      make_entry("native-add-bucket-iam-member", {"<role>", "<member>"},
                 NativeAddBucketIamMember),
      make_entry("native-add-bucket-conditional-iam-binding",
                 {"<role>", "<member>", "<condition-title>",
                  "<condition-description>", "<condition-expression>"},
                 NativeAddBucketConditionalIamBinding),
      make_entry("remove-bucket-iam-member", {"<role>", "<member>"},
                 RemoveBucketIamMember),
      make_entry("native-remove-bucket-conditional-iam-binding",
                 {"<role>", "<condition-title>", "<condition-description>",
                  "<condition-expression>"},
                 NativeRemoveBucketConditionalIamBinding),
      make_entry("native-remove-bucket-iam-member", {},
                 NativeRemoveBucketIamMember),
      // Cannot use make_entry(), it parses a variable number of arguments
      {"test-bucket-iam-permissions", TestBucketIamPermissions},
      make_entry("set-bucket-public-iam", {}, SetBucketPublicIam),
      make_entry("native-set-bucket-public-iam", {}, NativeSetBucketPublicIam),
      {"auto", RunAll},
  });
  return example.Run(argc, argv);
}
