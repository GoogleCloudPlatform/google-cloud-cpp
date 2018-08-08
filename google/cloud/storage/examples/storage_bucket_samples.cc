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
#include <functional>
#include <iostream>
#include <map>
#include <sstream>

namespace {
struct Usage {
  std::string msg;
};

char const* ConsumeArg(int& argc, char* argv[]) {
  if (argc < 2) {
    return nullptr;
  }
  char const* result = argv[1];
  std::copy(argv + 2, argv + argc, argv + 1);
  argc--;
  return result;
}

std::string command_usage;

void PrintUsage(int argc, char* argv[], std::string const& msg) {
  std::string const cmd = argv[0];
  auto last_slash = std::string(cmd).find_last_of('/');
  auto program = cmd.substr(last_slash + 1);
  std::cerr << msg << "\nUsage: " << program << " <command> [arguments]\n\n"
            << "Commands:\n"
            << command_usage << std::endl;
}

void ListBuckets(google::cloud::storage::Client client, int& argc,
                 char* argv[]) {
  if (argc != 1) {
    throw Usage{"list-buckets"};
  }
  //! [list buckets] [START storage_list_buckets]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client) {
    int count = 0;
    for (gcs::BucketMetadata const& meta : client.ListBuckets()) {
      std::cout << meta.name() << std::endl;
      ++count;
    }
    if (count == 0) {
      std::cout << "No buckets in default project" << std::endl;
    }
  }
  //! [list buckets] [END storage_list_buckets]
  (std::move(client));
}

void ListBucketsForProject(google::cloud::storage::Client client, int& argc,
                           char* argv[]) {
  if (argc != 2) {
    throw Usage{"list-buckets-for-project <project-id>"};
  }
  auto project_id = ConsumeArg(argc, argv);
  //! [list buckets for project]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string project_id) {
    int count = 0;
    for (gcs::BucketMetadata const& meta :
         client.ListBucketsForProject(project_id)) {
      std::cout << meta.name() << std::endl;
      ++count;
    }
    if (count == 0) {
      std::cout << "No buckets in project " << project_id << std::endl;
    }
  }
  //! [list buckets for project]
  (std::move(client), project_id);
}

void CreateBucket(google::cloud::storage::Client client, int& argc,
                  char* argv[]) {
  if (argc != 2) {
    throw Usage{"create-bucket <bucket-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  //! [create bucket] [START storage_create_bucket]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name) {
    gcs::BucketMetadata meta =
        client.CreateBucket(bucket_name, gcs::BucketMetadata());
    std::cout << "Bucket created.  The metadata is " << meta << std::endl;
  }
  //! [create bucket] [END storage_create_bucket]
  (std::move(client), bucket_name);
}

void CreateBucketForProject(google::cloud::storage::Client client, int& argc,
                            char* argv[]) {
  if (argc != 3) {
    throw Usage{"create-bucket-for-project <bucket-name> <project-id>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto project_id = ConsumeArg(argc, argv);
  //! [create bucket for project]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string project_id) {
    gcs::BucketMetadata meta = client.CreateBucketForProject(
        bucket_name, project_id, gcs::BucketMetadata());
    std::cout << "Bucket created for project " << project_id << "."
              << " The metadata is " << meta << std::endl;
  }
  //! [create bucket for project]
  (std::move(client), bucket_name, project_id);
}

void GetBucketMetadata(google::cloud::storage::Client client, int& argc,
                       char* argv[]) {
  if (argc < 2) {
    throw Usage{"get-bucket-metadata <bucket-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  //! [get bucket metadata] [START storage_get_bucket_metadata]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name) {
    gcs::BucketMetadata meta = client.GetBucketMetadata(bucket_name);
    std::cout << "The metadata is " << meta << std::endl;
  }
  //! [get bucket metadata] [END storage_get_bucket_metadata]
  (std::move(client), bucket_name);
}

void DeleteBucket(google::cloud::storage::Client client, int& argc,
                  char* argv[]) {
  if (argc != 2) {
    throw Usage{"delete-bucket <bucket-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  //! [delete bucket] [START storage_delete_bucket]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name) {
    client.DeleteBucket(bucket_name);
  }
  //! [delete bucket] [END storage_delete_bucket]
  (std::move(client), bucket_name);
}
}  // anonymous namespace

int main(int argc, char* argv[]) try {
  // Create a client to communicate with Google Cloud Storage.
  //! [create client]
  google::cloud::storage::Client client;
  //! [create client]

  using CommandType =
      std::function<void(google::cloud::storage::Client, int&, char* [])>;
  std::map<std::string, CommandType> commands = {
      {"list-buckets", &ListBuckets},
      {"list-buckets-for-project", &ListBucketsForProject},
      {"create-bucket", &CreateBucket},
      {"create-bucket-for-project", &CreateBucketForProject},
      {"get-bucket-metadata", &GetBucketMetadata},
      {"delete-bucket", &DeleteBucket},
  };
  for (auto&& kv : commands) {
    try {
      int fake_argc = 1;
      kv.second(client, fake_argc, argv);
    } catch (Usage const& u) {
      command_usage += "    ";
      command_usage += u.msg;
      command_usage += "\n";
    } catch (...) {
      // ignore other exceptions.
    }
  }

  if (argc < 2) {
    PrintUsage(argc, argv, "Missing command");
    return 1;
  }

  std::string const command = ConsumeArg(argc, argv);
  auto it = commands.find(command);
  if (commands.end() == it) {
    PrintUsage(argc, argv, "Unknown command: " + command);
    return 1;
  }

  it->second(client, argc, argv);

  return 0;
} catch (Usage const& ex) {
  PrintUsage(argc, argv, ex.msg);
  return 1;
} catch (std::exception const& ex) {
  std::cerr << "Standard C++ exception raised: " << ex.what() << std::endl;
  return 1;
}
