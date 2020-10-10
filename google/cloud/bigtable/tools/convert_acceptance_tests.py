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
    curl -L 'https://raw.githubusercontent.com/googleapis/conformance-tests/master/bigtable/v2/readrows.json' \
      | python ../tools/convert_acceptance_tests.py \
      | clang-format >readrowsparser_acceptance_tests.inc

"""
from __future__ import print_function

import json
import sys


FILE_HEADER = """
// AUTOGENERATED BY tools/convert_acceptance_tests.py; DO NOT EDIT MANUALLY.
// ALL MANUAL CHANGES WILL BE OVERWRITTEN.
//
// Copyright 2019 Google LLC
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
    words = "".join([c for c in s if c.isalpha() or c == " "]).split(" ")
    return "".join([w[:1].upper() + w[1:].lower() for w in words])


def print_test(t):
    o = '// Test name: "' + t["description"] + '"\n'
    o += "TEST_F(AcceptanceTest, " + camel_case(t["description"]) + ") {\n"

    o += "  std::vector<std::string> chunk_strings = {\n"
    if ('chunks' in t):
        for c in t["chunks"]:
            o += '      R"chunk(\n'
	    if ('rowKey' in c):
                o += '      rowKey: "' + c['rowKey'] + '"\n'
	    if ('familyName' in c):
	        o += '      familyName: "' + c['familyName'] + '"\n'
	    if ('qualifier' in c):
                o += '      qualifier: "' + c["qualifier"] + '"\n'
	    if ('timestampMicros' in c):
                o += '      timestampMicros: "' + str(c["timestampMicros"]) + '"\n'
	    if ('value' in c):
                o += '      value: "' + c["value"] + '"\n'
	    if ('commitRow' in c):
                o += '      commitRow: "' + unicode(c["commitRow"]) + '"\n' 
            o += '        )chunk",\n'
    if o[-1] == "\n":
        o += "  "	
    o += "  };\n"
    o += "\n"

    o += "  auto chunks = ConvertChunks(std::move(chunk_strings));\n"
    o += "  ASSERT_FALSE(chunks.empty());\n"

    o += "\n"

    ok = True
    if ('results' in t):
       	#try:
	    if ('error' in t["results"]):
                ok = not any([r["error"] for r in t["results"]])
	#except KeyError:
	    #raise ValueError('No "error" key in "%s"' % (r, ))

    if ok:
        o += "EXPECT_STATUS_OK(FeedChunks(chunks));\n"
    else:
        o += "EXPECT_FALSE(FeedChunks(chunks).ok());\n"

    o += "\n"
    o += "  std::vector<std::string> expected_cells = {"
    if ('results' in t):
        for r in t["results"]:
           o += "\n"
	   if ('rowKey' in r):
	       o += '      "rowKey: ' + r["rowKey"] + '\\n"\n'
	   if ('familyName' in r):
               o += '      "familyName: ' + r["familyName"] + '\\n"\n'
	   if ('qualifier' in r):
               o += '      "qualifier: ' + r["qualifier"] + '\\n"\n'
	   if ('timestampMicros' in r):
               o += '      "timestampMicros: ' + str(r["timestampMicros"]) + '\\n"\n'
	   if ('value' in r):
               o += '      "value: ' + r["value"] + '\\n"\n'
	   if ('label' in r):
               o += '      "label: ' + r["label"] + ',\\n"\n'

    if o[-1] == "\n":
        o += "  "
    o += "};\n"

    o += "  EXPECT_EQ(expected_cells, ExtractCells());\n"
    o += "}\n"
    return o


def main():
    t = json.loads(sys.stdin.read())

    print(FILE_HEADER.lstrip())
    for tt in t["readRowsTests"]:
        print(print_test(tt))


if __name__ == "__main__":
    main()
