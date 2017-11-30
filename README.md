# Google Cloud Platform C++ Client Libraries

[![Travis CI status][travis-shield]][travis-link]
[![Codecov Coverage status][codecov-shield]][codecov-link]

[travis-shield]: https://travis-ci.org/GoogleCloudPlatform/google-cloud-cpp.svg
[travis-link]: https://travis-ci.org/GoogleCloudPlatform/google-cloud-cpp/builds
[codecov-shield]: https://codecov.io/gh/GoogleCloudPlatform/google-cloud-cpp/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/GoogleCloudPlatform/google-cloud-cpp

This repo contains experimental client libraries for the following APIs:

* [Google Cloud Bigtable](bigtable/)

The libraries in this code base likely do not (yet) cover all the available
APIs. See the [`googleapis` repo](https://github.com/googleapis/googleapis)
for the full list of APIs callable using gRPC.

To build the available libraries and run the tests, run the following commands
after cloning this repo:

```sh
git submodule init
git submodule update --init --recursive
mkdir build-output
cd build-output
cmake ..
make all
make test
```

## Contributing changes

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details on how to contribute to
this project.

The code in this project is formatted with `clang-format(1)`, and our CI builds
will check that the code matches the format generated by this tool before
accepting a pull request. Please configure your editor or IDE to use the Google
style for indentation and whitespace. If you need to reformat one or more files
you can simply:

```console
clang-format -i <file>....
```

Reformatting all the files in a specific directory should be safe too, for 
example:

```console
$ find bigtable -o -name '*.h' -o -name '*.cc' -print0 \
    | xargs -0 clang-format -i
sample output
```

If you need to reformat one of the files to match the Google style.  Please be
advised that `clang-format` has been known to generate slightly different
formatting in different versions, we use version 4.0, use the same version if
you run into problems.

## Licensing

Apache 2.0; see [`LICENSE`](LICENSE) for details.
