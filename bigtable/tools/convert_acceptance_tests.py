# Copyright 2017 Google Inc.
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

"""Generate C++ unit tests from JSON acceptance tests.

The Bigtable Client ReadRows acceptance tests are specified in the
file `read-rows-acceptance-test.json` from

  https://github.com/GoogleCloudPlatform/cloud-bigtable-client

This script reads the JSON test cases and writes out C++ source code
in googletest style to run as unit tests for the ReadRows response
parser.

Usage:

    curl -L 'https://raw.githubusercontent.com/GoogleCloudPlatform/cloud-bigtable-client/master/bigtable-client-core-parent/bigtable-client-core/src/test/resources/com/google/cloud/bigtable/grpc/scanner/read-rows-acceptance-test.json' \
      | python ../../tools/convert_acceptance_tests.py \
      | clang-format >readrowsparser_acceptance_tests.inc
"""

import json
import sys


FILE_HEADER = """
// AUTOGENERATED BY tools/convert_acceptance_tests.py; DO NOT EDIT MANUALLY.
// ALL MANUAL CHANGES WILL BE OVERWRITTEN.
//
// Copyright 2017 Google Inc.
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
"""


def camel_case(s):
    words = ''.join([c for c in s if c.isalpha() or c == ' ']).split(' ')
    return ''.join([w[:1].upper() + w[1:].lower() for w in words])


def print_test(t):
    o = '// Test name: "' + t['name'] + '"\n'
    o += 'TEST_F(AcceptanceTest, ' + camel_case(t['name']) + ') {\n'

    o += '  std::vector<std::string> chunk_strings = {\n'
    for c in t['chunks']:
        s = c.rstrip()
        s = s.replace('<\n ', '<')
        s = s.replace('\n>', '>')
        s = s.replace('\n', '\n          ')
        o += '      R"chunk(\n'
        o += '          ' + s + '\n'
        o += '        )chunk",\n'
    o += '  };\n'
    o += '\n'

    o += '  auto chunks = ConvertChunks(std::move(chunk_strings));\n'
    o += '  ASSERT_FALSE(chunks.empty());\n'

    o += '\n'

    ok = True
    if t['results']:
        ok = not any([r['error'] for r in t['results']])

    if ok:
        o += '  EXPECT_NO_THROW(FeedChunks(chunks));\n'
    else:
        o += '  EXPECT_THROW(FeedChunks(chunks), std::exception);\n'

    o += '\n'
    o += '  std::vector<std::string> expected_cells = {'
    if t['results']:
        for r in t['results']:
            if not r['error']:
                o += '\n'
                o += '      "rk: ' + r['rk'] + '\\n"\n'
                o += '      "fm: ' + r['fm'] + '\\n"\n'
                o += '      "qual: ' + r['qual'] + '\\n"\n'
                o += '      "ts: ' + str(r['ts']) + '\\n"\n'
                o += '      "value: ' + r['value'] + '\\n"\n'
                o += '      "label: ' + r['label'] + '\\n",\n'

    if o[-1] == '\n':
        o += '  '
    o += '};\n'

    o += '  EXPECT_EQ(expected_cells, ExtractCells());\n'
    o += '}\n'
    return o


def main():
    t = json.loads(sys.stdin.read())

    print FILE_HEADER.lstrip()
    for tt in t['tests']:
        print print_test(tt)


if __name__ == '__main__':
    main()
