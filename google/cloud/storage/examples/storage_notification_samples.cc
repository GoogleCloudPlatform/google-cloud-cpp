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

void ListNotifications(google::cloud::storage::Client client, int& argc,
                       char* argv[]) {
  if (argc != 2) {
    throw Usage{"list-notifications <bucket-name>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  //! [list notifications] [START storage_list_bucket_notifications]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name) {
    std::cout << "Notifications for bucket=" << bucket_name << std::endl;
    for (gcs::NotificationMetadata const& notification :
         client.ListNotifications(bucket_name)) {
      std::cout << notification << std::endl;
    }
  }
  //! [list notifications] [END storage_list_bucket_notifications]
  (std::move(client), bucket_name);
}

void CreateNotification(google::cloud::storage::Client client, int& argc,
                        char* argv[]) {
  if (argc != 3) {
    throw Usage{"create-notification <bucket-name> <topic>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto topic_name = ConsumeArg(argc, argv);
  //! [create notification] [START storage_create_pubsub_bucket_notification]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string topic_name) {
    gcs::NotificationMetadata notification = client.CreateNotification(
        bucket_name, topic_name, gcs::payload_format::JsonApiV1(),
        gcs::NotificationMetadata());
    std::cout << "Successfully created notification " << notification.id()
              << " for bucket " << bucket_name
              << "\nfull details=" << notification << std::endl;
  }
  //! [create notification] [END storage_create_pubsub_bucket_notification]
  (std::move(client), bucket_name, topic_name);
}

void GetNotification(google::cloud::storage::Client client, int& argc,
                     char* argv[]) {
  if (argc != 3) {
    throw Usage{"get-notification <bucket-name> <notification-id>"};
  }
  auto bucket_name = ConsumeArg(argc, argv);
  auto notification_id = ConsumeArg(argc, argv);
  //! [get notification] [START storage_print_pubsub_bucket_notification]
  namespace gcs = google::cloud::storage;
  [](gcs::Client client, std::string bucket_name, std::string notification_id) {
    auto notification = client.GetNotification(bucket_name, notification_id);
    std::cout << "Notification " << notification.id() << " for bucket "
              << bucket_name << " details=" << notification << std::endl;
  }
  //! [get notification] [END storage_print_pubsub_bucket_notification]
  (std::move(client), bucket_name, notification_id);
}

}  // anonymous namespace

int main(int argc, char* argv[]) try {
  // Create a client to communicate with Google Cloud Storage.
  google::cloud::storage::Client client;

  // Build the list of commands and the usage string from that list.
  using CommandType =
      std::function<void(google::cloud::storage::Client, int&, char* [])>;
  std::map<std::string, CommandType> commands = {
      {"list-notifications", &ListNotifications},
      {"create-notification", &CreateNotification},
      {"get-notification", &GetNotification},
  };
  for (auto&& kv : commands) {
    try {
      int fake_argc = 1;
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

  // Call the command with that client.
  it->second(client, argc, argv);

  return 0;
} catch (Usage const& ex) {
  PrintUsage(argc, argv, ex.msg);
  return 1;
} catch (std::exception const& ex) {
  std::cerr << "Standard C++ exception raised: " << ex.what() << std::endl;
  return 1;
}
