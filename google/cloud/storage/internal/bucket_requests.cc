// Copyright 2018 Google LLC
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

#include "google/cloud/storage/internal/bucket_requests.h"
#include "google/cloud/storage/internal/bucket_acl_requests.h"
#include "google/cloud/storage/internal/object_acl_requests.h"
#include "google/cloud/internal/format_time_point.h"
#include "absl/strings/str_format.h"
#include "absl/time/civil_time.h"
#include <nlohmann/json.hpp>
#include <sstream>

namespace google {
namespace cloud {
namespace storage {
inline namespace STORAGE_CLIENT_NS {
namespace internal {
namespace {
CorsEntry ParseCors(nlohmann::json const& json) {
  auto parse_string_list = [](nlohmann::json const& json,
                              char const* field_name) {
    std::vector<std::string> list;
    if (json.count(field_name) != 0) {
      for (auto const& kv : json[field_name].items()) {
        list.emplace_back(kv.value().get<std::string>());
      }
    }
    return list;
  };
  CorsEntry result;
  if (json.count("maxAgeSeconds") != 0) {
    result.max_age_seconds = internal::ParseLongField(json, "maxAgeSeconds");
  }
  result.method = parse_string_list(json, "method");
  result.origin = parse_string_list(json, "origin");
  result.response_header = parse_string_list(json, "responseHeader");
  return result;
}

void SetIfNotEmpty(nlohmann::json& json, char const* key,
                   std::string const& value) {
  if (value.empty()) {
    return;
  }
  json[key] = value;
}

UniformBucketLevelAccess ParseUniformBucketLevelAccess(
    nlohmann::json const& json) {
  UniformBucketLevelAccess result;
  result.enabled = internal::ParseBoolField(json, "enabled");
  result.locked_time = internal::ParseTimestampField(json, "lockedTime");
  return result;
}

}  // namespace

StatusOr<LifecycleRule> LifecycleRuleParser::FromJson(
    nlohmann::json const& json) {
  if (!json.is_object()) {
    return Status(StatusCode::kInvalidArgument, __func__);
  }
  LifecycleRule result;
  if (json.count("action") != 0) {
    result.action_.type = json["action"].value("type", "");
    result.action_.storage_class = json["action"].value("storageClass", "");
  }
  if (json.count("condition") != 0) {
    auto condition = json["condition"];
    if (condition.count("age") != 0) {
      result.condition_.age.emplace(internal::ParseIntField(condition, "age"));
    }
    if (condition.count("createdBefore") != 0) {
      auto const date = condition.value("createdBefore", "");
      absl::CivilDay day;
      if (!absl::ParseCivilTime(date, &day)) {
        return Status(
            StatusCode::kInvalidArgument,
            "Cannot parse createdBefore value (" + date + "( as a date");
      }
      result.condition_.created_before.emplace(std::move(day));
    }
    if (condition.count("isLive") != 0) {
      result.condition_.is_live.emplace(
          internal::ParseBoolField(condition, "isLive"));
    }
    if (condition.count("matchesStorageClass") != 0) {
      std::vector<std::string> matches;
      for (auto const& kv : condition["matchesStorageClass"].items()) {
        matches.emplace_back(kv.value().get<std::string>());
      }
      result.condition_.matches_storage_class.emplace(std::move(matches));
    }
    if (condition.count("numNewerVersions") != 0) {
      result.condition_.num_newer_versions.emplace(
          internal::ParseIntField(condition, "numNewerVersions"));
    }
    if (condition.count("daysSinceNoncurrentTime") != 0) {
      result.condition_.days_since_noncurrent_time.emplace(
          internal::ParseIntField(condition, "daysSinceNoncurrentTime"));
    }
    if (condition.count("noncurrentTimeBefore") != 0) {
      auto const date = condition.value("noncurrentTimeBefore", "");
      absl::CivilDay day;
      if (!absl::ParseCivilTime(date, &day)) {
        return Status(
            StatusCode::kInvalidArgument,
            "Cannot parse noncurrentTimeBefore value (" + date + ") as a date");
      }
      result.condition_.noncurrent_time_before.emplace(std::move(day));
    }
  }
  return result;
}

StatusOr<LifecycleRule> LifecycleRuleParser::FromString(
    std::string const& text) {
  auto json = nlohmann::json::parse(text, nullptr, false);
  return FromJson(json);
}

StatusOr<BucketMetadata> BucketMetadataParser::FromJson(
    nlohmann::json const& json) {
  if (!json.is_object()) {
    return Status(StatusCode::kInvalidArgument, __func__);
  }
  BucketMetadata result{};
  auto status = CommonMetadata<BucketMetadata>::ParseFromJson(result, json);
  if (!status.ok()) {
    return status;
  }

  if (json.count("acl") != 0) {
    for (auto const& kv : json["acl"].items()) {
      auto parsed = internal::BucketAccessControlParser::FromJson(kv.value());
      if (!parsed.ok()) {
        return std::move(parsed).status();
      }
      result.acl_.emplace_back(std::move(*parsed));
    }
  }
  if (json.count("billing") != 0) {
    auto billing = json["billing"];
    BucketBilling b;
    b.requester_pays = internal::ParseBoolField(billing, "requesterPays");
    result.billing_ = b;
  }
  if (json.count("cors") != 0) {
    for (auto const& kv : json["cors"].items()) {
      result.cors_.emplace_back(ParseCors(kv.value()));
    }
  }
  if (json.count("defaultEventBasedHold") != 0) {
    result.default_event_based_hold_ =
        json.value("defaultEventBasedHold", false);
  }
  if (json.count("defaultObjectAcl") != 0) {
    for (auto const& kv : json["defaultObjectAcl"].items()) {
      auto parsed = ObjectAccessControlParser::FromJson(kv.value());
      if (!parsed.ok()) {
        return std::move(parsed).status();
      }
      result.default_acl_.emplace_back(std::move(*parsed));
    }
  }
  if (json.count("encryption") != 0) {
    BucketEncryption e;
    e.default_kms_key_name = json["encryption"].value("defaultKmsKeyName", "");
    result.encryption_ = std::move(e);
  }

  if (json.count("iamConfiguration") != 0) {
    BucketIamConfiguration c;
    auto config = json["iamConfiguration"];
    if (config.count("uniformBucketLevelAccess") != 0) {
      c.uniform_bucket_level_access =
          ParseUniformBucketLevelAccess(config["uniformBucketLevelAccess"]);
      c.bucket_policy_only =
          ParseUniformBucketLevelAccess(config["uniformBucketLevelAccess"]);
    }
    // Applications written before UBLA was introduced may have set only BPO,
    // only in this case we use the BPO value.  Applications that set UBLA are
    // assumed to prefer UBLA values, and would rarely have a reason to set
    // both.
    if (config.count("uniformBucketLevelAccess") == 0 &&
        config.count("bucketPolicyOnly") != 0) {
      c.uniform_bucket_level_access =
          ParseUniformBucketLevelAccess(config["bucketPolicyOnly"]);
      c.bucket_policy_only =
          ParseUniformBucketLevelAccess(config["bucketPolicyOnly"]);
    }
    result.iam_configuration_ = c;
  }

  if (json.count("lifecycle") != 0) {
    auto lifecycle = json["lifecycle"];
    BucketLifecycle value;
    if (lifecycle.count("rule") != 0) {
      for (auto const& kv : lifecycle["rule"].items()) {
        auto parsed = internal::LifecycleRuleParser::FromJson(kv.value());
        if (!parsed.ok()) {
          return std::move(parsed).status();
        }
        value.rule.emplace_back(std::move(*parsed));
      }
    }
    result.lifecycle_ = std::move(value);
  }

  result.location_ = json.value("location", "");

  result.location_type_ = json.value("locationType", "");

  if (json.count("logging") != 0) {
    auto logging = json["logging"];
    BucketLogging l;
    l.log_bucket = logging.value("logBucket", "");
    l.log_object_prefix = logging.value("logObjectPrefix", "");
    result.logging_ = std::move(l);
  }
  result.project_number_ = internal::ParseLongField(json, "projectNumber");
  if (json.count("labels") > 0) {
    for (auto const& kv : json["labels"].items()) {
      result.labels_.emplace(kv.key(), kv.value().get<std::string>());
    }
  }

  if (json.count("retentionPolicy") != 0) {
    auto retention_policy = json["retentionPolicy"];
    BucketRetentionPolicy r;
    r.retention_period = std::chrono::seconds(
        internal::ParseLongField(retention_policy, "retentionPeriod"));
    r.effective_time =
        internal::ParseTimestampField(retention_policy, "effectiveTime");
    r.is_locked = internal::ParseBoolField(retention_policy, "isLocked");
    result.retention_policy_ = r;
  }

  if (json.count("versioning") != 0) {
    auto versioning = json["versioning"];
    if (versioning.count("enabled") != 0) {
      BucketVersioning v{internal::ParseBoolField(versioning, "enabled")};
      result.versioning_ = v;
    }
  }

  if (json.count("website") != 0) {
    auto website = json["website"];
    BucketWebsite w;
    w.main_page_suffix = website.value("mainPageSuffix", "");
    w.not_found_page = website.value("notFoundPage", "");
    result.website_ = std::move(w);
  }
  return result;
}

StatusOr<BucketMetadata> BucketMetadataParser::FromString(
    std::string const& payload) {
  auto json = nlohmann::json::parse(payload, nullptr, false);
  return FromJson(json);
}

std::string BucketMetadataToJsonString(BucketMetadata const& meta) {
  nlohmann::json metadata_as_json;
  if (!meta.acl().empty()) {
    for (BucketAccessControl const& a : meta.acl()) {
      nlohmann::json entry;
      SetIfNotEmpty(entry, "entity", a.entity());
      SetIfNotEmpty(entry, "role", a.role());
      metadata_as_json["acl"].emplace_back(std::move(entry));
    }
  }

  if (!meta.cors().empty()) {
    for (CorsEntry const& v : meta.cors()) {
      nlohmann::json cors_as_json;
      if (v.max_age_seconds.has_value()) {
        cors_as_json["maxAgeSeconds"] = *v.max_age_seconds;
      }
      if (!v.method.empty()) {
        cors_as_json["method"] = v.method;
      }
      if (!v.origin.empty()) {
        cors_as_json["origin"] = v.origin;
      }
      if (!v.response_header.empty()) {
        cors_as_json["responseHeader"] = v.response_header;
      }
      metadata_as_json["cors"].emplace_back(std::move(cors_as_json));
    }
  }

  if (meta.has_billing()) {
    nlohmann::json b{
        {"requesterPays", meta.billing().requester_pays},
    };
    metadata_as_json["billing"] = std::move(b);
  }

  metadata_as_json["defaultEventBasedHold"] = meta.default_event_based_hold();

  if (!meta.default_acl().empty()) {
    for (ObjectAccessControl const& a : meta.default_acl()) {
      nlohmann::json entry;
      SetIfNotEmpty(entry, "entity", a.entity());
      SetIfNotEmpty(entry, "role", a.role());
      metadata_as_json["defaultObjectAcl"].emplace_back(std::move(entry));
    }
  }

  if (meta.has_encryption()) {
    nlohmann::json e;
    SetIfNotEmpty(e, "defaultKmsKeyName",
                  meta.encryption().default_kms_key_name);
    metadata_as_json["encryption"] = std::move(e);
  }

  if (meta.has_iam_configuration()) {
    nlohmann::json c;
    if (meta.iam_configuration().uniform_bucket_level_access.has_value()) {
      nlohmann::json ubla;
      ubla["enabled"] =
          meta.iam_configuration().uniform_bucket_level_access->enabled;
      // The lockedTime field is not mutable and should not be set by the client
      // the server will provide a value.
      c["uniformBucketLevelAccess"] = std::move(ubla);

      // Uniform Bucket Level Access(UBLA) is the new name for Bucket Policy
      // Only (BPO). UBLA is preferred and recommended over BPO but currently
      // both fields are supported. At the moment both fields being set is
      // required but this is a workaround and will be fixed when the feature
      // GA's in GCS.
      nlohmann::json bpo;
      bpo["enabled"] =
          meta.iam_configuration().uniform_bucket_level_access->enabled;
      // The lockedTime field is not mutable and should not be set by the client
      // the server will provide a value.
      c["bucketPolicyOnly"] = std::move(bpo);
    }
    // Uniform Bucket Level Access(UBLA) is the new name for Bucket Policy
    // Only (BPO). UBLA is preferred and recommended over BPO. The UBLA field
    // must be populated for bucket metadata JSON object including legacy
    // applications having  only `bucketPolicyOnly`(legacy). This will ensure
    // continual support for legacy applications.
    if (!meta.iam_configuration().uniform_bucket_level_access.has_value() &&
        meta.iam_configuration().bucket_policy_only.has_value()) {
      nlohmann::json ubla;
      ubla["enabled"] = meta.iam_configuration().bucket_policy_only->enabled;
      // The lockedTime field is not mutable and should not be set by the client
      // the server will provide a value.
      c["uniformBucketLevelAccess"] = std::move(ubla);
      nlohmann::json bpo;
      bpo["enabled"] = meta.iam_configuration().bucket_policy_only->enabled;
      // The lockedTime field is not mutable and should not be set by the client
      // the server will provide a value.
      c["bucketPolicyOnly"] = std::move(bpo);
    }
    metadata_as_json["iamConfiguration"] = std::move(c);
  }

  if (!meta.labels().empty()) {
    nlohmann::json labels_as_json;
    for (auto const& kv : meta.labels()) {
      labels_as_json[kv.first] = kv.second;
    }
    metadata_as_json["labels"] = std::move(labels_as_json);
  }

  if (meta.has_lifecycle()) {
    nlohmann::json rule;
    for (LifecycleRule const& v : meta.lifecycle().rule) {
      nlohmann::json condition;
      auto const& c = v.condition();
      if (c.age) {
        condition["age"] = *c.age;
      }
      if (c.created_before.has_value()) {
        condition["createdBefore"] =
            absl::StrFormat("%04d-%02d-%02d", c.created_before->year(),
                            c.created_before->month(), c.created_before->day());
      }
      if (c.is_live) {
        condition["isLive"] = *c.is_live;
      }
      if (c.matches_storage_class) {
        condition["matchesStorageClass"] = *c.matches_storage_class;
      }
      if (c.num_newer_versions) {
        condition["numNewerVersions"] = *c.num_newer_versions;
      }
      nlohmann::json action{{"type", v.action().type}};
      if (!v.action().storage_class.empty()) {
        action["storageClass"] = v.action().storage_class;
      }
      rule.emplace_back(nlohmann::json{{"condition", std::move(condition)},
                                       {"action", std::move(action)}});
    }
    metadata_as_json["lifecycle"] = nlohmann::json{{"rule", std::move(rule)}};
  }

  SetIfNotEmpty(metadata_as_json, "location", meta.location());

  SetIfNotEmpty(metadata_as_json, "locationType", meta.location_type());

  if (meta.has_logging()) {
    nlohmann::json l;
    SetIfNotEmpty(l, "logBucket", meta.logging().log_bucket);
    SetIfNotEmpty(l, "logObjectPrefix", meta.logging().log_object_prefix);
    metadata_as_json["logging"] = std::move(l);
  }

  SetIfNotEmpty(metadata_as_json, "name", meta.name());

  if (meta.has_retention_policy()) {
    nlohmann::json r{
        {"retentionPeriod", meta.retention_policy().retention_period.count()}};
    metadata_as_json["retentionPolicy"] = std::move(r);
  }

  SetIfNotEmpty(metadata_as_json, "storageClass", meta.storage_class());

  if (meta.versioning().has_value()) {
    metadata_as_json["versioning"] =
        nlohmann::json{{"enabled", meta.versioning()->enabled}};
  }

  if (meta.has_website()) {
    nlohmann::json w;
    SetIfNotEmpty(w, "mainPageSuffix", meta.website().main_page_suffix);
    SetIfNotEmpty(w, "notFoundPage", meta.website().not_found_page);
    metadata_as_json["website"] = std::move(w);
  }

  return metadata_as_json.dump();
}

std::ostream& operator<<(std::ostream& os, ListBucketsRequest const& r) {
  os << "ListBucketsRequest={project_id=" << r.project_id();
  r.DumpOptions(os, ", ");
  return os << "}";
}

StatusOr<ListBucketsResponse> ListBucketsResponse::FromHttpResponse(
    std::string const& payload) {
  auto json = nlohmann::json::parse(payload, nullptr, false);
  if (!json.is_object()) {
    return Status(StatusCode::kInvalidArgument, __func__);
  }

  ListBucketsResponse result;
  result.next_page_token = json.value("nextPageToken", "");

  for (auto const& kv : json["items"].items()) {
    auto parsed = internal::BucketMetadataParser::FromJson(kv.value());
    if (!parsed) {
      return std::move(parsed).status();
    }
    result.items.emplace_back(std::move(*parsed));
  }

  return result;
}

std::ostream& operator<<(std::ostream& os, ListBucketsResponse const& r) {
  os << "ListBucketsResponse={next_page_token=" << r.next_page_token
     << ", items={";
  std::copy(r.items.begin(), r.items.end(),
            std::ostream_iterator<BucketMetadata>(os, "\n  "));
  return os << "}}";
}

std::ostream& operator<<(std::ostream& os, GetBucketMetadataRequest const& r) {
  os << "GetBucketMetadataRequest={bucket_name=" << r.bucket_name();
  r.DumpOptions(os, ", ");
  return os << "}";
}

std::ostream& operator<<(std::ostream& os, CreateBucketRequest const& r) {
  os << "CreateBucketRequest={project_id=" << r.project_id()
     << ", metadata=" << r.metadata();
  r.DumpOptions(os, ", ");
  return os << "}";
}

std::ostream& operator<<(std::ostream& os, DeleteBucketRequest const& r) {
  os << "DeleteBucketRequest={bucket_name=" << r.bucket_name();
  r.DumpOptions(os, ", ");
  return os << "}";
}

std::ostream& operator<<(std::ostream& os, UpdateBucketRequest const& r) {
  os << "UpdateBucketRequest={metadata=" << r.metadata();
  r.DumpOptions(os, ", ");
  return os << "}";
}

PatchBucketRequest::PatchBucketRequest(std::string bucket,
                                       BucketMetadata const& original,
                                       BucketMetadata const& updated)
    : bucket_(std::move(bucket)) {
  // Compare each modifiable field to build the patch
  BucketMetadataPatchBuilder builder;

  if (original.acl() != updated.acl()) {
    builder.SetAcl(updated.acl());
  }

  if (original.billing_as_optional() != updated.billing_as_optional()) {
    if (updated.has_billing()) {
      builder.SetBilling(updated.billing());
    } else {
      builder.ResetBilling();
    }
  }

  if (original.cors() != updated.cors()) {
    builder.SetCors(updated.cors());
  }

  if (original.default_event_based_hold() !=
      updated.default_event_based_hold()) {
    builder.SetDefaultEventBasedHold(updated.default_event_based_hold());
  }

  if (original.default_acl() != updated.default_acl()) {
    builder.SetDefaultAcl(updated.default_acl());
  }

  if (original.encryption_as_optional() != updated.encryption_as_optional()) {
    if (updated.has_encryption()) {
      builder.SetEncryption(updated.encryption());
    } else {
      builder.ResetEncryption();
    }
  }

  if (original.iam_configuration_as_optional() !=
      updated.iam_configuration_as_optional()) {
    if (updated.has_iam_configuration()) {
      builder.SetIamConfiguration(updated.iam_configuration());
    } else {
      builder.ResetIamConfiguration();
    }
  }

  if (original.labels() != updated.labels()) {
    if (updated.labels().empty()) {
      builder.ResetLabels();
    } else {
      std::map<std::string, std::string> difference;
      // Find the keys in the original map that are not in the new map:
      std::set_difference(original.labels().begin(), original.labels().end(),
                          updated.labels().begin(), updated.labels().end(),
                          std::inserter(difference, difference.end()),
                          // We want to compare just keys and ignore values, the
                          // map class provides such a function, so use it:
                          original.labels().value_comp());
      for (auto&& d : difference) {
        builder.ResetLabel(d.first);
      }

      // Find the elements (comparing key and value) in the updated map that
      // are not in the original map:
      difference.clear();
      std::set_difference(updated.labels().begin(), updated.labels().end(),
                          original.labels().begin(), original.labels().end(),
                          std::inserter(difference, difference.end()));
      for (auto&& d : difference) {
        builder.SetLabel(d.first, d.second);
      }
    }
  }

  if (original.lifecycle_as_optional() != updated.lifecycle_as_optional()) {
    if (updated.has_lifecycle()) {
      builder.SetLifecycle(updated.lifecycle());
    } else {
      builder.ResetLifecycle();
    }
  }

  if (original.logging_as_optional() != updated.logging_as_optional()) {
    if (updated.has_logging()) {
      builder.SetLogging(updated.logging());
    } else {
      builder.ResetLogging();
    }
  }

  if (original.name() != updated.name()) {
    builder.SetName(updated.name());
  }

  if (original.retention_policy_as_optional() !=
      updated.retention_policy_as_optional()) {
    if (updated.has_retention_policy()) {
      builder.SetRetentionPolicy(updated.retention_policy());
    } else {
      builder.ResetRetentionPolicy();
    }
  }

  if (original.storage_class() != updated.storage_class()) {
    builder.SetStorageClass(updated.storage_class());
  }

  if (original.versioning() != updated.versioning()) {
    if (updated.has_versioning()) {
      builder.SetVersioning(*updated.versioning());
    } else {
      builder.ResetVersioning();
    }
  }

  if (original.website_as_optional() != updated.website_as_optional()) {
    if (updated.has_website()) {
      builder.SetWebsite(updated.website());
    } else {
      builder.ResetWebsite();
    }
  }

  payload_ = builder.BuildPatch();
}

PatchBucketRequest::PatchBucketRequest(std::string bucket,
                                       BucketMetadataPatchBuilder const& patch)
    : bucket_(std::move(bucket)), payload_(patch.BuildPatch()) {}

std::ostream& operator<<(std::ostream& os, PatchBucketRequest const& r) {
  os << "PatchBucketRequest={bucket_name=" << r.bucket();
  r.DumpOptions(os, ", ");
  return os << ", payload=" << r.payload() << "}";
}

std::ostream& operator<<(std::ostream& os, GetBucketIamPolicyRequest const& r) {
  os << "GetBucketIamPolicyRequest={bucket_name=" << r.bucket_name();
  r.DumpOptions(os, ", ");
  return os << "}";
}

StatusOr<IamPolicy> ParseIamPolicyFromString(std::string const& payload) {
  auto json = nlohmann::json::parse(payload, nullptr, false);
  if (!json.is_object()) {
    return Status(StatusCode::kInvalidArgument, __func__);
  }
  IamPolicy policy;
  policy.version = 0;
  policy.etag = json.value("etag", "");
  if (json.count("bindings") != 0) {
    if (!json["bindings"].is_array()) {
      std::ostringstream os;
      os << "Invalid IamPolicy payload, expected array for 'bindings' field."
         << "  payload=" << payload;
      return Status(StatusCode::kInvalidArgument, os.str());
    }
    for (auto const& kv : json["bindings"].items()) {
      auto binding = kv.value();
      if (!binding.is_object()) {
        std::ostringstream os;
        // TODO(#2732): Advise alternative API after it's implemented.
        os << "Invalid IamPolicy payload, expected objects for 'bindings' "
              "entries."
           << "  payload=" << payload;
        return Status(StatusCode::kInvalidArgument, os.str());
      }
      for (auto const& binding_kv : binding.items()) {
        auto const& key = binding_kv.key();
        if (key != "members" && key != "role") {
          std::ostringstream os;
          os << "Invalid IamPolicy payload, unexpected member '" << key
             << "' in element #" << kv.key() << ". payload=" << payload;
          return Status(StatusCode::kInvalidArgument, os.str());
        }
      }
      if (binding.count("role") == 0 or binding.count("members") == 0) {
        std::ostringstream os;
        os << "Invalid IamPolicy payload, expected 'role' and 'members'"
           << " fields for element #" << kv.key() << ". payload=" << payload;
        return Status(StatusCode::kInvalidArgument, os.str());
      }
      if (!binding["members"].is_array()) {
        std::ostringstream os;
        os << "Invalid IamPolicy payload, expected array for 'members'"
           << " fields for element #" << kv.key() << ". payload=" << payload;
        return Status(StatusCode::kInvalidArgument, os.str());
      }
      std::string role = binding.value("role", "");
      for (auto const& member : binding["members"].items()) {
        policy.bindings.AddMember(role, member.value());
      }
    }
  }
  return policy;
}  // namespace internal

SetBucketIamPolicyRequest::SetBucketIamPolicyRequest(
    std::string bucket_name, google::cloud::IamPolicy const& policy)
    : bucket_name_(std::move(bucket_name)) {
  nlohmann::json iam{
      {"kind", "storage#policy"},
      {"etag", policy.etag},
  };
  nlohmann::json bindings;
  for (auto const& binding : policy.bindings) {
    nlohmann::json b{
        {"role", binding.first},
    };
    nlohmann::json m;
    for (auto const& member : binding.second) {
      m.emplace_back(member);
    }
    b["members"] = std::move(m);
    bindings.emplace_back(std::move(b));
  }
  iam["bindings"] = std::move(bindings);
  json_payload_ = iam.dump();
}

std::ostream& operator<<(std::ostream& os, SetBucketIamPolicyRequest const& r) {
  os << "GetBucketIamPolicyRequest={bucket_name=" << r.bucket_name();
  r.DumpOptions(os, ", ");
  return os << ", json_payload=" << r.json_payload() << "}";
}

SetNativeBucketIamPolicyRequest::SetNativeBucketIamPolicyRequest(
    std::string bucket_name, NativeIamPolicy const& policy)
    : bucket_name_(std::move(bucket_name)), json_payload_(policy.ToJson()) {
  if (!policy.etag().empty()) {
    set_option(IfMatchEtag(policy.etag()));
  }
}

std::ostream& operator<<(std::ostream& os,
                         SetNativeBucketIamPolicyRequest const& r) {
  os << "SetNativeBucketIamPolicyRequest={bucket_name=" << r.bucket_name();
  r.DumpOptions(os, ", ");
  return os << ", json_payload=" << r.json_payload() << "}";
}

std::ostream& operator<<(std::ostream& os,
                         TestBucketIamPermissionsRequest const& r) {
  os << "TestBucketIamPermissionsRequest={bucket_name=" << r.bucket_name()
     << ", permissions=[";
  char const* sep = "";
  for (auto const& p : r.permissions()) {
    os << sep << p;
    sep = ", ";
  }
  os << "]";
  r.DumpOptions(os, ", ");
  return os << "}";
}

StatusOr<TestBucketIamPermissionsResponse>
TestBucketIamPermissionsResponse::FromHttpResponse(std::string const& payload) {
  TestBucketIamPermissionsResponse result;
  auto json = nlohmann::json::parse(payload, nullptr, false);
  if (!json.is_object()) {
    return Status(StatusCode::kInvalidArgument, __func__);
  }
  for (auto const& kv : json["permissions"].items()) {
    result.permissions.emplace_back(kv.value().get<std::string>());
  }
  return result;
}

std::ostream& operator<<(std::ostream& os,
                         TestBucketIamPermissionsResponse const& r) {
  os << "TestBucketIamPermissionsResponse={permissions=[";
  char const* sep = "";
  for (auto const& p : r.permissions) {
    os << sep << p;
    sep = ", ";
  }
  return os << "]}";
}

std::ostream& operator<<(std::ostream& os,
                         LockBucketRetentionPolicyRequest const& r) {
  os << "LockBucketRetentionPolicyRequest={bucket_name=" << r.bucket_name()
     << ", metageneration=" << r.metageneration();
  r.DumpOptions(os, ", ");
  return os << "}";
};

}  // namespace internal
}  // namespace STORAGE_CLIENT_NS
}  // namespace storage
}  // namespace cloud
}  // namespace google
