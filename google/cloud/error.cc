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

#include "google/cloud/error.h"
#include <iostream>
#include <mutex>

namespace google {
namespace cloud {
inline namespace GOOGLE_CLOUD_CPP_NS {
namespace {

class TerminateFunction {
 public:
  TerminateFunction(TerminateHandler&& f) {
    std::lock_guard<std::mutex> l(m_);
    f_ = std::move(f);
  }

  TerminateHandler Get() {
    std::lock_guard<std::mutex> l(m_);
    return f_;
  }

  void Set(TerminateHandler&& f) {
    std::lock_guard<std::mutex> l(m_);
    f_ = std::move(f);
  }

 private:
  TerminateHandler f_;
  std::mutex m_;
};

TerminateFunction& GetTerminateHolder() {
  static TerminateFunction f([](const char* msg) {
    std::cerr << "Aborting because exceptions are disabled: " << msg
              << std::endl;
    std::abort();
  });
  return f;
}

}  // anonymous namespace

void SetTerminateHandler(TerminateHandler&& f) {
  GetTerminateHolder().Set(std::move(f));
}

TerminateHandler GetTerminateHandler() { return GetTerminateHolder().Get(); }

[[noreturn]] void Terminate(const char* msg) {
  GetTerminateHolder().Get()(msg);
  std::cerr << "Aborting because the installed terminate handler returned. "
               "Error details: "
            << msg << std::endl;
  std::abort();
}

}  // namespace GOOGLE_CLOUD_CPP_NS
}  // namespace cloud
}  // namespace google
