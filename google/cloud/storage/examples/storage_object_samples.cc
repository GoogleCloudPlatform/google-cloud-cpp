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

void ListObjects(google::cloud::storage::Client client, int& argc,
                 char* argv[]) {
  if (argc < 2) {
    throw Usage{"list-objects <bucket-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  //! [list objects] [START storage_list_files]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name) {
    for (gcs::ObjectMetadata const& meta : client.ListObjects(bucket_name)) {
      std::cout << "bucket_name=" << meta.bucket()
                << ", object_name=" << meta.name() << std::endl;
    }
  }
  //! [list objects] [END storage_list_files]
  (std::move(client), bucket_name);
}

void InsertObject(google::cloud::storage::Client client, int& argc,
                  char* argv[]) {
  if (argc < 3) {
    throw Usage{
        "insert-object <bucket-name> <object-name> <object-contents (string)>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto contents = ConsumeArg(argc, argv);
  //! [insert object] [START storage_upload_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string contents) {
    gcs::ObjectMetadata meta =
        client.InsertObject(bucket_name, object_name, std::move(contents));
    std::cout << "The file was uploaded. The new object metadata is " << meta
              << std::endl;
  }
  //! [insert object] [END storage_upload_file]
  (std::move(client), bucket_name, object_name, contents);
}

void GetObjectMetadata(google::cloud::storage::Client client, int& argc,
                       char* argv[]) {
  if (argc < 3) {
    throw Usage{"get-object-metadata <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [get object metadata] [START storage_get_metadata]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name) {
    gcs::ObjectMetadata meta =
        client.GetObjectMetadata(bucket_name, object_name);
    std::cout << "The metadata is " << meta << std::endl;
  }
  //! [get object metadata] [END storage_get_metadata]
  (std::move(client), bucket_name, object_name);
}

void ReadObject(google::cloud::storage::Client client, int& argc,
                char* argv[]) {
  if (argc < 2) {
    throw Usage{"read-object <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [read object]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name) {
    gcs::ObjectReadStream stream = client.ReadObject(bucket_name, object_name);
    int count = 0;
    while (not stream.eof()) {
      std::string line;
      std::getline(stream, line, '\n');
      ++count;
    }
    std::cout << "The object has " << count << " lines" << std::endl;
  }
  //! [read object]
  (std::move(client), bucket_name, object_name);
}

void DeleteObject(google::cloud::storage::Client client, int& argc,
                  char* argv[]) {
  if (argc < 2) {
    throw Usage{"delete-object <bucket-name> <object-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  //! [delete object] [START storage_delete_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name) {
    client.DeleteObject(bucket_name, object_name);
    std::cout << "Deleted " << object_name << " in bucket " << bucket_name
              << std::endl;
  }
  //! [delete object] [END storage_delete_file]
  (std::move(client), bucket_name, object_name);
}

void WriteObject(google::cloud::storage::Client client, int& argc,
                 char* argv[]) {
  if (argc < 3) {
    throw Usage{
        "write-object <bucket-name> <object-name> <target-object-line-count>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto desired_line_count = std::stol(ConsumeArg(argc, argv));

  //! [write object]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     long desired_line_count) {
    std::string const text = "Lorem ipsum dolor sit amet";
    gcs::ObjectWriteStream stream =
        client.WriteObject(bucket_name, object_name);

    for (int lineno = 0; lineno != desired_line_count; ++lineno) {
      // Add 1 to the counter, because it is conventional to number lines
      // starting at 1.
      stream << (lineno + 1) << ": " << text << "\n";
    }

    gcs::ObjectMetadata meta = stream.Close();
    std::cout << "The resulting object size is: " << meta.size() << std::endl;
  }
  //! [write object]
  (std::move(client), bucket_name, object_name, desired_line_count);
}

void GenerateEncryptionKey(google::cloud::storage::Client client, int& argc,
                           char* argv[]) {
  if (argc != 1) {
    throw Usage{"generate-encryption-key"};
  }
  //! [generate encryption key] [START generate_encryption_key_base64]
  // Create a pseudo-random number generator (PRNG), this is included for
  // demonstration purposes only. You should consult your security team about
  // best practices to initialize PRNG. In particular, you should verify that
  // the C++ library and operating system provide enough entropy to meet the
  // security policies in your organization.

  // Use the Mersenne-Twister Engine in this example:
  //   https://en.cppreference.com/w/cpp/numeric/random/mersenne_twister_engine
  // Any C++ PRNG can be used below, the choice is arbitrary.
  using GeneratorType = std::mt19937_64;

  // Create the default random device to fetch entropy.
  std::random_device rd;

  // Compute how much entropy we need to initialize the GeneratorType:
  constexpr auto kRequiredEntropyWords =
      GeneratorType::state_size *
      (GeneratorType::word_size / std::numeric_limits<unsigned int>::digits);

  // Capture the entropy bits into a vector.
  std::vector<unsigned long> entropy(kRequiredEntropyWords);
  std::generate(entropy.begin(), entropy.end(), [&rd] { return rd(); });

  // Create the PRNG with the fetched entropy.
  std::seed_seq seed(entropy.begin(), entropy.end());
  GeneratorType gen(seed);

  namespace gcs = google::cloud::storage;
  gcs::EncryptionKeyData data = gcs::CreateKeyFromGenerator(gen);

  std::cout << "Base64 encoded key = " << data.key << "\n"
            << "Base64 encoded SHA256 of key = " << data.sha256 << std::endl;
  //! [generate encryption key] [END generate_encryption_key_base64]
}

void WriteEncryptedObject(google::cloud::storage::Client client, int& argc,
                          char* argv[]) {
  if (argc != 4) {
    throw Usage{
        "write-encrypted-object <bucket-name> <object-name> <raw-aes256-key>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto raw_aes256_key = ConsumeArg(argc, argv);
  //! [insert encrypted object] [START storage_upload_encrypted_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string raw_aes256_key) {
    gcs::ObjectMetadata meta =
        client.InsertObject(bucket_name, object_name, "top secret",
                            gcs::EncryptionKey::FromBinaryKey(raw_aes256_key));
    std::cout << "The object was created. The new object metadata is " << meta
              << std::endl;
  }
  //! [insert encrypted object] [END storage_upload_encrypted_file]
  (std::move(client), bucket_name, object_name, raw_aes256_key);
}

void ReadEncryptedObject(google::cloud::storage::Client client, int& argc,
                         char* argv[]) {
  if (argc != 4) {
    throw Usage{
        "read-encrypted-object <bucket-name> <object-name> <raw-aes256-key>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto object_name = ConsumeArg(argc, argv);
  auto raw_aes256_key = ConsumeArg(argc, argv);
  //! [read encrypted object] [START storage_download_encrypted_file]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string object_name,
     std::string raw_aes256_key) {
    gcs::ObjectReadStream stream =
        client.ReadObject(bucket_name, object_name,
                          gcs::EncryptionKey::FromBinaryKey(raw_aes256_key));
    std::string data(std::istreambuf_iterator<char>{stream}, {});
    std::cout << "The object contents are: " << data << std::endl;
  }
  //! [read encrypted object] [END storage_download_encrypted_file]
  (std::move(client), bucket_name, object_name, raw_aes256_key);
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
      {"list-objects", &ListObjects},
      {"insert-object", &InsertObject},
      {"get-object-metadata", &GetObjectMetadata},
      {"read-object", &ReadObject},
      {"delete-object", &DeleteObject},
      {"write-object", &WriteObject},
      {"generate-encryption-key", &GenerateEncryptionKey},
      {"write-encrypted-object", &WriteEncryptedObject},
      {"read-encrypted-object", &ReadEncryptedObject},
  };
  for (auto&& kv : commands) {
    try {
      int fake_argc = 0;
      kv.second(client, fake_argc, argv);
    } catch (Usage const& u) {
      command_usage += "    ";
      command_usage += u.msg;
      command_usage += "\n";
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
