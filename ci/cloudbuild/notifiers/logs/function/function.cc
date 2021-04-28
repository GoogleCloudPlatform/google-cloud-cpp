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

#include <google/cloud/functions/cloud_event.h>
#include <google/cloud/storage/client.h>
#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <libgen.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

auto constexpr kGcsPrefix = "https://storage.googleapis.com/";
auto constexpr kPrPrefix = "https://github.com/googleapis/google-cloud-cpp/pull/";
auto constexpr kGCBPrefix = "https://console.cloud.google.com/cloud-build/builds?project=";
auto constexpr kAttempts = 4;

using ::google::cloud::StatusCode;
using ::google::cloud::functions::CloudEvent;
namespace gcs = ::google::cloud::storage;

namespace {

// Returns an HTML anchor referencing the given URL with the optional name. If
// `name` is not specified, the URL is used as the text.
std::string anchor(std::string const& url, std::string name = "") {
  if (name.empty()) name = url;
  return "<a href=\"" + url + "\">" + name + "</a>";
}

// Writes a 2-column HTML table w/ the data from the vector.
void write_table(std::ostream& os,
                 std::vector<std::pair<std::string, std::string>> const& v) {
  os << "<table>\n";
  for (auto const& e : v) {
    os << "<tr>";
    os << "<td>" << e.first << "</td>";
    os << "<td>" << e.second << "</td>";
    os << "</tr>\n";
  }
  os << "</table>";
}

// The log files include a component like <distro>-<script>, but the GitHub
// status UI shows trigger names, like `clang-tidy-pr`. To make it easier for
// customers to correlate these logs w/ the builds that fail in the GitHub UI,
// we split the logfile component into the separate build parts so we can
// render links with the same name.
struct BuildName {
  std::string distro;
  std::string script;
  std::string trigger;
};
BuildName MakeBuildName(std::string const& distro_script) {
  auto hyphen = distro_script.find('-');
  if (hyphen == std::string::npos) {
    throw std::runtime_error("No hyphen in distro_script: " + distro_script);
  }
  BuildName bn;
  bn.distro = distro_script.substr(0, hyphen);
  bn.script = distro_script.substr(hyphen + 1) + ".sh";
  bn.trigger = bn.script + "-pr";
  return bn;
}

}  // namespace

void index_build_logs(CloudEvent event) {  // NOLINT
  static auto client = [] {
    return gcs::Client::CreateDefaultClient().value();
  }();
  static auto const bucket_name = [] {
    auto const* bname = std::getenv("BUCKET_NAME");
    if (bname == nullptr) {
      throw std::runtime_error("BUCKET_NAME environment variable is required");
    }
    return std::string{bname};
  }();

  if (event.data_content_type().value_or("") != "application/json") {
    std::cerr << nlohmann::json{{"severity", "error"},
                     {"message", "expected application/json data"},
                                }
                     .dump()
              << "\n";
    return;
  }
  auto const payload = nlohmann::json::parse(event.data().value_or("{}"));
  if (payload.count("message") == 0) {
    std::cerr << nlohmann::json{{"severity", "error"},
                                {"message", "missing embedded Pub/Sub message"}}
                     .dump()
              << "\n";
    return;
  }
  auto const message = payload["message"];
  if (message.count("attributes") == 0 or message.count("data") == 0) {
    std::cerr << nlohmann::json{{"severity", "error"},
                                {"message",
                                 "missing Pub/Sub attributes or data"}}
                     .dump()
              << "\n";
    return;
  }
  // Queued builds do not have any logs, skip them.
  if (message["attributes"].value("status", "") == "QUEUED") return;
  auto const data = cppcodec::base64_rfc4648::decode<std::string>(
      message["data"].get<std::string>());
  auto const contents = nlohmann::json::parse(data);
  auto const trigger_type =
      contents["substitutions"].value("_TRIGGER_TYPE", "");
  if (trigger_type != "pr") {
    std::cout << nlohmann::json{{"severity", "info"},
                                {"message", "skipping non-PR build"}}
                     .dump()
              << "\n";
    return;
  }

  auto const pr = contents["substitutions"].value("_PR_NUMBER", "");
  auto const sha = contents["substitutions"].value("COMMIT_SHA", "");
  auto const prefix = "logs/google-cloud-cpp/" + pr + "/" + sha + "/";
  auto const project = contents["projectId"].get<std::string>();

  static auto const kIndexRE =
      std::regex(R"re(/index\.html$)re", std::regex::optimize);
  static auto const kLogfileRE =
      std::regex(R"re(/log-[0-9a-f-]+\.txt$)re", std::regex::optimize);

  std::vector<std::pair<std::string, std::string>> v;
  v.emplace_back("Repo", anchor("https://github.com/googleapis/google-cloud-cpp"));
  v.emplace_back("Pull Request", anchor(kPrPrefix + pr, "#" + pr));
  v.emplace_back("Commit SHA", anchor(kPrPrefix + pr + "/commits/" + sha, sha));
  v.emplace_back("GCB Console",
                 anchor(kGCBPrefix + project + "&query=tags%3D%22" + pr + "%22",
                        "(requires auth)"));

  std::int64_t index_generation = 0;
  for (int i = 0; i != kAttempts; ++i) {
    std::ostringstream os;
    os << "<!DOCTYPE html>\n";
    os << "<html><head><meta charset=\"utf-8\"></head>\n";
    os << "<body>\n";
    os << "<h1>Public Build Logs</h1>";
    write_table(os, v);
    os << "<ul>\n";
    for (auto const& object :
         client.ListObjects(bucket_name, gcs::Prefix(prefix))) {
      if (!object) throw std::runtime_error(object.status().message());
      if (std::regex_search(object->name(), kIndexRE)) {
        index_generation = object->generation();
        continue;
      }
      if (!std::regex_search(object->name(), kLogfileRE)) continue;
      auto path = object->name();
      auto const build_name = MakeBuildName(basename(dirname(path.data())));
      os << "<li>";
      os << anchor(kGcsPrefix + bucket_name + "/" + object->name(), build_name.trigger);
      os << "</li>\n";
    }
    os << "</ul>\n";
    os << "</body>\n";
    os << "</html>\n";
    // Use `IfGenerationMatch()` to prevent overwriting data. It is possible
    // that the data written concurrently was more up to date. Note that
    // (conveniently) `IfGenerationMatch(0)` means "if the object does not
    // exist".
    auto metadata = client.InsertObject(
        bucket_name, prefix + "index.html", os.str(),
        gcs::IfGenerationMatch(index_generation),
        gcs::WithObjectMetadata(gcs::ObjectMetadata{}
                                    .set_content_type("text/html")
                                    .set_cache_control("no-cache")));
    if (metadata.ok()) return;
    // If the write fail for any reason other than a failed precondition that is
    // an error.
    if (metadata.status().code() != StatusCode::kFailedPrecondition) {
      throw std::runtime_error(metadata.status().message());
    }
  }
}
