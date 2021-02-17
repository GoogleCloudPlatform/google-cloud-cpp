#!/usr/bin/env bash
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eu

GOLDEN_FILE_MD5_HASHES=(
  "ea1b8609a3f41ac268fd8c4dd77e5456  generator/integration_tests/golden/golden_kitchen_sink_client.gcpcxx.pb.cc"
  "9c1d65bd83ef66dbe2a29a1a45c73078  generator/integration_tests/golden/golden_kitchen_sink_client.gcpcxx.pb.h"
  "f21b41e0e3b5e8a46ae9bb12daa3935f  generator/integration_tests/golden/golden_kitchen_sink_connection.gcpcxx.pb.cc"
  "a50f9e6058066f1fd64dee26fce10ccf  generator/integration_tests/golden/golden_kitchen_sink_connection.gcpcxx.pb.h"
  "a39836d43ed8d594389c8cef1eae1ea4  generator/integration_tests/golden/golden_kitchen_sink_connection_idempotency_policy.gcpcxx.pb.cc"
  "9f30c7b35f5982da8abfc3c599ad2ee6  generator/integration_tests/golden/golden_kitchen_sink_connection_idempotency_policy.gcpcxx.pb.h"
  "985f7d6e53d159108de4fbf15f88eff8  generator/integration_tests/golden/golden_thing_admin_client.gcpcxx.pb.cc"
  "b664e24fe8285b3c786914b51cc09465  generator/integration_tests/golden/golden_thing_admin_client.gcpcxx.pb.h"
  "24f72f5b5b26c4d44a7946fb9d3ea228  generator/integration_tests/golden/golden_thing_admin_connection.gcpcxx.pb.cc"
  "635288bc060d3e051c05cd0c5ff5a3eb  generator/integration_tests/golden/golden_thing_admin_connection.gcpcxx.pb.h"
  "cac495fb3054264260f204c204b697f0  generator/integration_tests/golden/golden_thing_admin_connection_idempotency_policy.gcpcxx.pb.cc"
  "9954827c1f873eaac4d20f1d39059624  generator/integration_tests/golden/golden_thing_admin_connection_idempotency_policy.gcpcxx.pb.h"
  "d0b70285cd28dab106f8df8878fa4556  generator/integration_tests/golden/internal/golden_kitchen_sink_logging_decorator.gcpcxx.pb.cc"
  "e147d81c7d66da36e3a13ba9af45f315  generator/integration_tests/golden/internal/golden_kitchen_sink_logging_decorator.gcpcxx.pb.h"
  "d75b7afad61340a7991850fe56e0b15c  generator/integration_tests/golden/internal/golden_kitchen_sink_metadata_decorator.gcpcxx.pb.cc"
  "7ca011c36b0f4d7af364c88b0bab998d  generator/integration_tests/golden/internal/golden_kitchen_sink_metadata_decorator.gcpcxx.pb.h"
  "5a6926917dc874e6cf41ef47dfc259ed  generator/integration_tests/golden/internal/golden_kitchen_sink_stub_factory.gcpcxx.pb.cc"
  "aff5b79e7983ae2c6bc583405547cb17  generator/integration_tests/golden/internal/golden_kitchen_sink_stub_factory.gcpcxx.pb.h"
  "9d6de0c25daeddf1b546797439f4869c  generator/integration_tests/golden/internal/golden_kitchen_sink_stub.gcpcxx.pb.cc"
  "e72ad6212dd707940d8477a358650ace  generator/integration_tests/golden/internal/golden_kitchen_sink_stub.gcpcxx.pb.h"
  "2f5feb8f2b29aa5688fdd30af7af81f3  generator/integration_tests/golden/internal/golden_thing_admin_logging_decorator.gcpcxx.pb.cc"
  "21d5a6b03b3e7108be287265d08fb7ab  generator/integration_tests/golden/internal/golden_thing_admin_logging_decorator.gcpcxx.pb.h"
  "f5983226514b7bc252dc05c71df86482  generator/integration_tests/golden/internal/golden_thing_admin_metadata_decorator.gcpcxx.pb.cc"
  "34cbc571321c8ba27adc757a99249bdc  generator/integration_tests/golden/internal/golden_thing_admin_metadata_decorator.gcpcxx.pb.h"
  "e9c8ae9040ad7d8ad0b46374441ecb8c  generator/integration_tests/golden/internal/golden_thing_admin_stub_factory.gcpcxx.pb.cc"
  "0c418b518bf96fb4903e5b8652ddb441  generator/integration_tests/golden/internal/golden_thing_admin_stub_factory.gcpcxx.pb.h"
  "110bae9fb1283100853b947c96877948  generator/integration_tests/golden/internal/golden_thing_admin_stub.gcpcxx.pb.cc"
  "13087e5db6cbe35eb92ade60ef97db14  generator/integration_tests/golden/internal/golden_thing_admin_stub.gcpcxx.pb.h"
  "bf748f48817f3bf1e164d92834d0919d  generator/integration_tests/golden/mocks/mock_golden_kitchen_sink_connection.gcpcxx.pb.h"
  "aed7ff6dc82e724deb6f9caafd54acb0  generator/integration_tests/golden/mocks/mock_golden_thing_admin_connection.gcpcxx.pb.h"
)

readonly GOLDEN_FILE_MD5_HASHES
