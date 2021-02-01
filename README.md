# Google Cloud Platform C++ Client Libraries

<!-- This file is automatically generated by ci/test-markdown/generate-readme.sh -->

[![Kokoro CI status][kokoro-clang-tidy-shield]][kokoro-clang-tidy-link]
[![Kokoro CI status][kokoro-windows-cmake-shield]][kokoro-windows-cmake-link]
[![Kokoro CI status][kokoro-macos-cmake-shield]][kokoro-macos-cmake-link]
[![Codecov Coverage status][codecov-shield]][codecov-link]<br>
[![Kokoro CI status][kokoro-integration-shield]][kokoro-integration-link]
[![Kokoro CI status][kokoro-windows-bazel-shield]][kokoro-windows-bazel-link]
[![Kokoro CI status][kokoro-macos-bazel-shield]][kokoro-macos-bazel-link]

[kokoro-clang-tidy-shield]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-clang-tidy.svg
[kokoro-clang-tidy-link]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-clang-tidy-link.html
[kokoro-integration-shield]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-integration.svg
[kokoro-integration-link]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-integration-link.html
[kokoro-windows-cmake-shield]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-windows-cmake.svg
[kokoro-windows-cmake-link]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-windows-cmake-link.html
[kokoro-windows-bazel-shield]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-windows-bazel.svg
[kokoro-windows-bazel-link]: https://storage.googleapis.com/cloud-cpp-kokoro-status/kokoro-windows-bazel-link.html
[kokoro-macos-cmake-shield]: https://storage.googleapis.com/cloud-cpp-kokoro-status/macos/kokoro-cmake-super.svg
[kokoro-macos-cmake-link]: https://storage.googleapis.com/cloud-cpp-kokoro-status/macos/kokoro-cmake-super-link.html
[kokoro-macos-bazel-shield]: https://storage.googleapis.com/cloud-cpp-kokoro-status/macos/kokoro-bazel.svg
[kokoro-macos-bazel-link]: https://storage.googleapis.com/cloud-cpp-kokoro-status/macos/kokoro-bazel-link.html
[codecov-shield]: https://codecov.io/gh/googleapis/google-cloud-cpp/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/googleapis/google-cloud-cpp

This repository contains idiomatic C++ client libraries for the following
[Google Cloud Platform](https://cloud.google.com/) services.

* [Google Cloud Bigtable](google/cloud/bigtable/README.md) [[quickstart]](google/cloud/bigtable/quickstart/README.md)
* [Google Cloud Spanner](google/cloud/spanner/README.md) [[quickstart]](google/cloud/spanner/quickstart/README.md)
* [Google Cloud Pub/Sub](google/cloud/pubsub/README.md) [[quickstart]](google/cloud/pubsub/quickstart/README.md)
* [Google Cloud Storage](google/cloud/storage/README.md) [[quickstart]](google/cloud/storage/quickstart/README.md)

See each library's `README.md` file for more information about:

* Where to find the documentation for the library and the service.
* How to get started using the library.
* How to incorporate the library into your build system.
* The library's support status if not Generally Available (GA); unless noted in
  a library's `README.md`, these libraries are all GA and supported by Google.

## Install

On most platforms, with all dependencies installed, the following commands will
compile and install all the libraries:

```sh
cmake -H. -Bcmake-out
cmake --build cmake-out
sudo cmake --build cmake-out --target install
```

You can find detailed instructions on how to install and/or compile all the
dependencies for several platforms in the [packaging guide](doc/packaging.md).

For application developers who prefer to build from source, the quickstart
guides for each library (see above) include instructions on how to incorporate
the library into their CMake-based or Bazel-based builds.

## Quickstart

Each library (linked above) contains a directory named `quickstart/` that's
intended to help you get up and running in a matter of minutes. This
`quickstart/` directory contains a minimal "Hello World" program demonstrating
how to use the library, along with minimal build files for common build
systems, such as CMake and Bazel.

* [Google Cloud Bigtable Quickstart](google/cloud/bigtable/quickstart/README.md)
* [Google Cloud Spanner Quickstart](google/cloud/spanner/quickstart/README.md)
* [Google Cloud Pub/Sub Quickstart](google/cloud/pubsub/quickstart/README.md)
* [Google Cloud Storage Quickstart](google/cloud/storage/quickstart/README.md)

As an example, the following code snippet, taken from [Google Cloud
Storage](google/cloud/storage/README.md), should give you a taste of what it's
like to use one of these C++ libraries.

```cc
#include "google/cloud/storage/client.h"
#include <iostream>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "Missing bucket name.\n";
    std::cerr << "Usage: quickstart <bucket-name>\n";
    return 1;
  }
  std::string const bucket_name = argv[1];

  // Create aliases to make the code easier to read.
  namespace gcs = google::cloud::storage;

  // Create a client to communicate with Google Cloud Storage. This client
  // uses the default configuration for authentication and project id.
  google::cloud::StatusOr<gcs::Client> client =
      gcs::Client::CreateDefaultClient();
  if (!client) {
    std::cerr << "Failed to create Storage Client, status=" << client.status()
              << "\n";
    return 1;
  }

  auto writer = client->WriteObject(bucket_name, "quickstart.txt");
  writer << "Hello World!";
  writer.Close();
  if (writer.metadata()) {
    std::cout << "Successfully created object: " << *writer.metadata() << "\n";
  } else {
    std::cerr << "Error creating object: " << writer.metadata().status()
              << "\n";
    return 1;
  }

  auto reader = client->ReadObject(bucket_name, "quickstart.txt");
  if (!reader) {
    std::cerr << "Error reading object: " << reader.status() << "\n";
    return 1;
  }

  std::string contents{std::istreambuf_iterator<char>{reader}, {}};
  std::cout << contents << "\n";

  return 0;
}
```

## Support

* This project supports Windows, macOS, Linux
* This project supports C++11 (and higher) compilers (we test with GCC \>= 5.4, Clang >= 3.8, and MSVC \>= 2019)
* This project supports Bazel and CMake builds. See the [Quickstart examples](https://github.com/googleapis/google-cloud-cpp#quickstart)
* This project uses dependencies described in [doc/packaging.md](https://github.com/googleapis/google-cloud-cpp/blob/master/doc/packaging.md)
* This project works with or without exceptions enabled
* This project cuts [monthly releases](https://github.com/googleapis/google-cloud-cpp/releases) with detailed release notes

## Public API and API Breaking Changes

In general, we avoid making backwards incompatible changes to our C++ APIs (see
below for the definition of "API"). Sometimes such changes yield benefits to
our customers, in the form of better performance, easier-to-understand APIs,
and/or more consistent APIs across services. When these benefits warrant it, we
will announce these changes prominently in our `CHANGELOG.md` file and in the
affected release's notes. Nevertheless, though we take commercially reasonable
efforts to prevent this, it is possible that backwards incompatible changes go
undetected and, therefore, undocumented. We apologize if this is the case and
welcome feedback or bug reports to rectify the problem.

By "API" we mean the C++ API exposed by public header files in this repo. We
are not talking about the gRPC or REST APIs exposed by Google Cloud servers. We
are also talking only about A**P**I stability -- the ABI is subject to change
without notice. You should not assume that binary artifacts (e.g. static
libraries, shared objects, dynamically loaded libraries, object files) created
with one version of the library are usable with newer/older versions of the
library. The ABI may, and does, change on "minor revisions", and even patch
releases.

We request that our customers adhere to the following guidelines to avoid
accidentally depending on parts of the library we do not consider to be part of
the public API and therefore may change (including removal) without notice:

Previous versions of the library will remain available on the [GitHub Releases
page](https://github.com/googleapis/google-cloud-cpp/releases). In many cases,
you will be able to use an older version even if a newer version has changes
that you are unable (or do not have time) to adopt.

Note that this document has no bearing on the Google Cloud Platform deprecation
policy described at https://cloud.google.com/terms.

### C++ Symbols and Files

* You should only include headers matching the `google/cloud/${library}/*.h`,
  `google/cloud/${library}/mock/*.h` or `google/cloud/*.h` patterns.
* You should **NOT** directly include headers in any subdirectories, such as
  `google/cloud/${library}/internal`.
* The files *included from* our public headers are **not part of our public
  API**. Depending on indirect includes may break your build in the future, as
  we may change a header `"foo.h"` to stop including `"bar.h"` if `"foo.h"` no
  longer needs the symbols in `"bar.h"`. To avoid having your code broken, you
  should directly include the public headers that define all the symbols you
  use (this is sometimes known as
  [include-what-you-use](https://include-what-you-use.org/)).
* Any file or symbol that lives within a directory or namespace containing
  `internal`, `impl`, `test`, `detail`, `benchmark`, `sample`, or `example`, is
  explicitly **not part of our public API**.
* Any file or symbol with `Impl` or `impl` in its name is **not part of our
  public API**.
* Any symbol with `experimental` in its name is not part of the public API.

## Beyond the C++ API

Applications developers interact with a C++ library through more than just
the C++ symbols and headers. They also need to reference the name of the
library in their build scripts. Depending of the build system they use
this may be a CMake target, a Bazel rule, a pkg-config module, or just the
name of some object in the file system.

As with the C++ API, we try to avoid breaking changes to these interface
points. Sometimes such changes yield benefits to our customers, in the form of
easier-to-understand what names go with with services, or more consistency
across services. When these benefits warrant it, we will announce these changes
prominently in our `CHANGELOG.md` file and in the affected release's notes.
Nevertheless, though we take commercially reasonable efforts to prevent this,
it is possible that backwards incompatible changes go undetected and,
therefore, undocumented. We apologize if this is the case and welcome feedback
or bug reports to rectify the problem.

### Experimental Libraries

From time to time we add libraries to `google-cloud-cpp` to validate new
designs, expose experimental (or otherwise not generally available) GCP
features, or simply because a library is not yet complete. Such libraries
will have `experimental` in their CMake target and Bazel rule. The README
file for these libraries will also document that they are experimental.
Such libraries are subject to change, including removal, without notice.
This includes, but it is not limited to, all their symbols, pre-processor
macros, files, targets, rules, and installed artifacts.

### Bazel rules

Only the rules exported at the top-level directory are intended for customer
user, e.g.,`//:spanner`. Experimental rules have `experimental` in their name,
e.g. `//:experimental-firestore`, as previously stated, experimental rules are
subject to change or removal without notice.

Previously some of the rules in subdirectories
(e.g. `//google/cloud/bigtable:bigtable_client`) had public visibility. These
rules are deprecated as of 2021-02-15, and will be become inaccessible
(or removed) on or shortly after **2022-02-15**.

### CMake targets and packages

Only CMake packages starting with the `google_cloud_cpp_` prefix intended for
customer use. Only targets starting with `google-cloud-cpp::`, except
experimental targets, are intended for customer use. Experimental targets have
`experimental` in their name (e.g. `google-cloud-cpp::experimental-iam`), as
previously stated, experimental targets are subject to change or removal without
notice.

In previous versions we released packages with other prefixes (or without
specific prefixes), these are deprecated as of 2021-02-15, and will be retired
on or shortly after **2022-02-15**. Same applies to any targets exported with
other prefixes (or without an specific prefix).

### pkg-config modules

Only modules starting with `google_cloud_cpp_` are intended for customer use.

In previous versions we released modules with other prefixes (or without
specific prefixes), these are deprecated as of 2021-02-15, and will be retired
on or shortly after **2022-02-15**.

### Unsupported use cases

We try to provide stable names for the previously described mechanisms:

* Bazel rules,
* CMake targets loaded via `find_package()`,
* pkg-config modules

It is certainly possible to use the the library through other mechanisms,
and while these may work, we may accidentally break these from time to time.
Examples of such uses and the recommended alternatives include:

* CMake's FetchContent and/or git submodules: in these approaches the
  `google-cloud-cpp` library becomes a sub-directory of a larger CMake build
  We do not test `google-cloud-cpp` in this configuration, and we find it
  problematic as **all** CMake targets become visible to the larger project.
  This is both prone to conflicts, and makes it impossible to enforce that
  some targets are only for testing or implementation.
  Applications may want to consider source package managers, such as
  `vcpkg`, or should use CMake super builds via `ExternalProject_Add()`
  as alternatives.

* Using library names directly: applications should not use the
  library names, e.g., by using `-lgoogle_cloud_cpp_bigtable`
  in build scripts. We may need to split or merge libraries over time,
  making such names unstable. Applications should use CMake targets,
  e.g., `google-cloud-cpp::bigtable`, or pkg-config modules, e.g.,
  `$(pkg-config google_cloud_cpp_bigtable --libs)`.

### Documentation and Comments

The documentation (and its links) is intended for human consumption and not
third party websites, or automation (such as scripts scrapping the contents).
The contents and links of our documentation may change without notice.

### Other Interface Points

We think this covers all interface points, if we missed something please
file a [GitHub issue][github-issue].

## Contact us

If you have questions or comments, or want to file bugs or request feature,
please do so using GitHub's normal Issues mechanism: [Contact Us][github-issue]

[github-issue]: https://github.com/googleapis/google-cloud-cpp/issues/new/choose

## Contributing changes

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details on how to contribute to
this project, including how to build and test your changes as well as how to
properly format your code.

## Licensing

Apache 2.0; see [`LICENSE`](LICENSE) for details.
