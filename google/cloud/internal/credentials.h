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

#ifndef GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_CREDENTIALS_H
#define GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_CREDENTIALS_H

#include "google/cloud/status_or.h"
#include "google/cloud/version.h"
#include "absl/types/optional.h"
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {
namespace internal {
class CredentialsVisitor;
}  // namespace internal

// TODO(#6293) - move unified credentials out of internal namespace
namespace internal {
class Credentials {
 public:
  virtual ~Credentials() = 0;

 private:
  friend class CredentialsVisitor;
  virtual void dispatch(CredentialsVisitor& visitor) = 0;
};

std::shared_ptr<Credentials> MakeGoogleDefaultCredentials();
std::shared_ptr<Credentials> MakeAccessTokenCredentials(
    std::string const& access_token,
    std::chrono::system_clock::time_point expiration);

/// A wrapper to store credentials into an options
struct UnifiedCredentialsOption {
  using Type = std::shared_ptr<Credentials>;
};

}  // namespace internal

namespace internal {

/// Represents an access token with a known expiration time.
struct AccessToken {
  std::string token;
  std::chrono::system_clock::time_point expiration;
};

class GoogleDefaultCredentialsConfig;
class AccessTokenConfig;

class CredentialsVisitor {
 public:
  virtual ~CredentialsVisitor() = default;
  virtual void visit(GoogleDefaultCredentialsConfig&) = 0;
  virtual void visit(AccessTokenConfig&) = 0;

  static void dispatch(Credentials& credentials, CredentialsVisitor& visitor);
};

class GoogleDefaultCredentialsConfig : public Credentials {
 public:
  ~GoogleDefaultCredentialsConfig() override = default;

 private:
  void dispatch(CredentialsVisitor& v) override { v.visit(*this); }
};

class AccessTokenConfig : public Credentials {
 public:
  AccessTokenConfig(std::string token,
                    std::chrono::system_clock::time_point expiration)
      : access_token_(AccessToken{std::move(token), expiration}) {}
  ~AccessTokenConfig() override = default;

  AccessToken const& access_token() const { return access_token_; }

 private:
  void dispatch(CredentialsVisitor& v) override { v.visit(*this); }

  AccessToken access_token_;
};

}  // namespace internal
}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google

#endif  // GOOGLE_CLOUD_CPP_GOOGLE_CLOUD_INTERNAL_CREDENTIALS_H
