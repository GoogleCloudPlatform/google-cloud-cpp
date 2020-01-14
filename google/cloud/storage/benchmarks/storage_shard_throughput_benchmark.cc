// Copyright 2019 Google LLC
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

#include "google/cloud/internal/build_info.h"
#include "google/cloud/internal/format_time_point.h"
#include "google/cloud/internal/getenv.h"
#include "google/cloud/internal/random.h"
#include "google/cloud/storage/benchmarks/benchmark_utils.h"
#include "google/cloud/storage/client.h"
#include <deque>
#include <future>
#include <iomanip>
#include <sstream>

namespace {
namespace gcs = google::cloud::storage;
namespace gcs_bm = google::cloud::storage_benchmarks;

char const kDescription[] = R"""(
A throughput benchmark for the Google Cloud Storage C++ client library.

This program first creates a bucket that will contain all the GCS objects used
in the test.  The bucket is deleted at the end of the test. The name of the
bucket is selected at random, so multiple instances of this benchmark can run
simultaneously. The bucket uses the `STANDARD` storage class, in a region set
via the command-line.

After creating this bucket the program creates a number of objects, all the
objects have the same contents, but the contents are generated at random.

The size of the objects can be configured in the command-line, by default they
are 240MiB in size. The objects are constructed by writing N identical
chunks, the size of these chunks is configured in the command-line.

Once the object creation phase is completed, the program starts T worker
threads. The worker threads read a queue of "chunks" to be downloaded, these
chunks are selected by the main thread at random.

The number of chunks selected by the main thread is configurable from the
command-line. After the prescribed number of chunks is generated by the main
thread, the program shuts down the worker queue, waits for all the worker
threads to finish, and reports the effective download throughput.

Then the program removes all the objects in the bucket and reports the time
taken to delete each one.

A helper script in this directory can generate pretty graphs from the output of
this program.
)""";

struct Options {
  std::string project_id;
  std::string bucket_prefix = "cloud-cpp-testing-";
  std::string region;
  int object_count = 100;
  int thread_count = 1;
  int iteration_size = 100;
  int iteration_count = 100;
  std::int64_t chunk_size = 12 * gcs_bm::kMiB;
  int chunk_count = 20;
};

template <typename T>
class BoundedQueue {
 public:
  BoundedQueue() : BoundedQueue(512, 1024) {}
  explicit BoundedQueue(std::size_t lwm, std::size_t hwm)
      : lwm_(lwm), hwm_(hwm), is_shutdown_(false) {}

  void Shutdown() {
    std::unique_lock<std::mutex> lk(mu_);
    is_shutdown_ = true;
    lk.unlock();
    cv_read_.notify_all();
    cv_write_.notify_all();
  }

  google::cloud::optional<T> Pop() {
    std::unique_lock<std::mutex> lk(mu_);
    cv_read_.wait(lk, [this]() { return is_shutdown_ || !empty(); });
    if (empty()) return {};
    auto next = std::move(buffer_.front());
    buffer_.pop_front();
    if (below_lwm()) {
      cv_write_.notify_all();
    }
    return next;
  }

  void Push(T data) {
    std::unique_lock<std::mutex> lk(mu_);
    cv_write_.wait(lk, [this]() { return is_shutdown_ || below_hwm(); });
    if (is_shutdown_) return;
    buffer_.push_back(std::move(data));
    cv_read_.notify_all();
  }

 private:
  bool empty() const { return buffer_.empty(); }
  bool below_hwm() const { return buffer_.size() <= hwm_; }
  bool below_lwm() const { return buffer_.size() <= lwm_; }

  std::size_t const lwm_;
  std::size_t const hwm_;
  std::mutex mu_;
  std::condition_variable cv_read_;
  std::condition_variable cv_write_;
  std::deque<T> buffer_;
  bool is_shutdown_ = false;
};

struct WorkItem {
  std::string bucket;
  std::string object;
  std::int64_t begin;
  std::int64_t end;
};

using WorkItemQueue = BoundedQueue<WorkItem>;

struct IterationResult {
  std::int64_t bytes;
  std::chrono::microseconds elapsed;
};
using TestResult = std::vector<IterationResult>;

std::vector<std::string> CreateAllObjects(
    gcs::Client client, google::cloud::internal::DefaultPRNG& gen,
    std::string const& bucket_name, Options const& options);

IterationResult RunOneIteration(google::cloud::internal::DefaultPRNG& generator,
                                Options const& options,
                                std::string const& bucket_name,
                                std::vector<std::string> const& object_names);

void DeleteAllObjects(gcs::Client client, std::string const& bucket_name,
                      Options const& options,
                      std::vector<std::string> const& object_names);

google::cloud::StatusOr<Options> ParseArgs(int argc, char* argv[]);

}  // namespace

int main(int argc, char* argv[]) {
  google::cloud::StatusOr<Options> options = ParseArgs(argc, argv);
  if (!options) {
    std::cerr << options.status() << "\n";
    return 1;
  }

  google::cloud::StatusOr<gcs::ClientOptions> client_options =
      gcs::ClientOptions::CreateDefaultClientOptions();
  if (!client_options) {
    std::cerr << "Could not create ClientOptions, status="
              << client_options.status() << "\n";
    return 1;
  }
  if (!options->project_id.empty()) {
    client_options->set_project_id(options->project_id);
  }
  gcs::Client client(*std::move(client_options));

  google::cloud::internal::DefaultPRNG generator =
      google::cloud::internal::MakeDefaultPRNG();

  auto bucket_name =
      gcs_bm::MakeRandomBucketName(generator, options->bucket_prefix);
  std::cout << "# Creating bucket " << bucket_name << " in region "
            << options->region << "\n";
  auto meta =
      client
          .CreateBucket(bucket_name,
                        gcs::BucketMetadata()
                            .set_storage_class(gcs::storage_class::Standard())
                            .set_location(options->region),
                        gcs::PredefinedAcl("private"),
                        gcs::PredefinedDefaultObjectAcl("projectPrivate"),
                        gcs::Projection("full"))
          .value();
  std::cout << "# Running test on bucket: " << meta.name() << "\n";
  std::string notes = google::cloud::storage::version_string() + ";" +
                      google::cloud::internal::compiler() + ";" +
                      google::cloud::internal::compiler_flags();
  std::transform(notes.begin(), notes.end(), notes.begin(),
                 [](char c) { return c == '\n' ? ';' : c; });
  std::cout << "# Start time: "
            << google::cloud::internal::FormatRfc3339(
                   std::chrono::system_clock::now())
            << "\n# Region: " << options->region
            << "\n# Object Count: " << options->object_count
            << "\n# Thread Count: " << options->thread_count
            << "\n# Iteration Size: " << options->iteration_size
            << "\n# Iteration Count: " << options->iteration_count
            << "\n# Chunk Size: " << options->chunk_size
            << "\n# Chunk Size (MiB): " << options->chunk_size / gcs_bm::kMiB
            << "\n# Chunk Count: " << options->chunk_count
            << "\n# Build info: " << notes << std::endl;

  std::vector<std::string> const object_names =
      CreateAllObjects(client, generator, bucket_name, *options);

  double MiBs_sum = 0.0;
  for (long i = 0; i != options->iteration_count; ++i) {
    auto const r =
        RunOneIteration(generator, *options, bucket_name, object_names);
    std::cout << r.bytes << ',' << r.elapsed.count() << std::endl;
    auto const MiB = r.bytes / gcs_bm::kMiB;
    auto const MiBs =
        MiB * (1.0 * decltype(r.elapsed)::period::den) / r.elapsed.count();
    MiBs_sum += MiBs;
  }

  auto const MiBs_avg = MiBs_sum / options->iteration_count;
  std::cout << "# Average Bandwidth (MiB/s): " << MiBs_avg << "\n";

  DeleteAllObjects(client, bucket_name, *options, object_names);

  std::cout << "# Deleting " << bucket_name << "\n";
  auto status = client.DeleteBucket(bucket_name);
  if (!status.ok()) {
    std::cerr << "# Error deleting bucket, status=" << status << "\n";
    return 1;
  }

  return 0;
}

namespace {

void CreateGroup(gcs::Client client, std::string const& bucket_name,
                 Options const& options, std::vector<std::string> group) {
  google::cloud::internal::DefaultPRNG generator =
      google::cloud::internal::MakeDefaultPRNG();

  std::string const random_data =
      gcs_bm::MakeRandomData(generator, options.chunk_size);
  for (auto const& object_name : group) {
    auto stream = client.WriteObject(bucket_name, object_name, gcs::Fields(""));
    for (std::int64_t count = 0; count != options.chunk_count; ++count) {
      stream.write(random_data.data(), random_data.size());
    }
    stream.Close();
    if (!stream.metadata()) {
      std::cerr << "Error writing: " << object_name << "\n";
    }
  }
}

std::vector<std::string> CreateAllObjects(
    gcs::Client client, google::cloud::internal::DefaultPRNG& gen,
    std::string const& bucket_name, Options const& options) {
  using std::chrono::duration_cast;
  using std::chrono::milliseconds;

  std::size_t const max_group_size =
      std::max(options.object_count / options.thread_count, 1);
  std::cout << "# Creating test objects [" << max_group_size << "]\n";

  // Generate the list of object names.
  std::vector<std::string> object_names;
  object_names.reserve(options.object_count);
  for (long c = 0; c != options.object_count; ++c) {
    object_names.emplace_back(gcs_bm::MakeRandomObjectName(gen));
  }

  // Split the objects in more or less equally sized groups, launch a thread
  // to create the objects in each group.
  auto start = std::chrono::steady_clock::now();
  std::vector<std::future<void>> tasks;
  std::vector<std::string> group;
  for (auto const& o : object_names) {
    group.push_back(o);
    if (group.size() >= max_group_size) {
      tasks.emplace_back(std::async(std::launch::async, &CreateGroup, client,
                                    bucket_name, options, std::move(group)));
      group = {};  // after a move, must assign to guarantee it is valid.
    }
  }
  if (!group.empty()) {
    tasks.emplace_back(std::async(std::launch::async, &CreateGroup, client,
                                  bucket_name, options, std::move(group)));
  }
  // Wait for the threads to finish.
  for (auto& t : tasks) {
    t.get();
  }
  auto elapsed = std::chrono::steady_clock::now() - start;
  std::cout << "# Created in " << duration_cast<milliseconds>(elapsed).count()
            << "ms\n";
  return object_names;
}

void WorkerThread(WorkItemQueue& work_queue) {
  auto client = gcs::Client::CreateDefaultClient();
  if (!client) return;
  std::vector<char> buffer;
  for (auto w = work_queue.Pop(); w.has_value(); w = work_queue.Pop()) {
    auto const begin = w->begin;
    auto const end = w->end;
    auto stream =
        client->ReadObject(w->bucket, w->object, gcs::ReadRange(begin, end));
    buffer.resize(w->end - w->begin);
    stream.read(buffer.data(), buffer.size());
    stream.Close();
  }
}

IterationResult RunOneIteration(google::cloud::internal::DefaultPRNG& generator,
                                Options const& options,
                                std::string const& bucket_name,
                                std::vector<std::string> const& object_names) {
  using std::chrono::duration_cast;
  using std::chrono::microseconds;

  WorkItemQueue work_queue;
  std::vector<std::future<void>> workers;
  std::generate_n(std::back_inserter(workers), options.thread_count,
                  [&work_queue] {
                    return std::async(std::launch::async, WorkerThread,
                                      std::ref(work_queue));
                  });

  std::uniform_int_distribution<std::size_t> object_generator(
      0, object_names.size() - 1);
  std::uniform_int_distribution<std::int64_t> chunk_generator(
      0, options.chunk_count - 1);

  auto const download_start = std::chrono::steady_clock::now();
  std::int64_t total_bytes = 0;
  for (long i = 0; i != options.iteration_size; ++i) {
    auto const object = object_generator(generator);
    auto const chunk = chunk_generator(generator);
    work_queue.Push({bucket_name, object_names.at(object),
                     chunk * options.chunk_size,
                     (chunk + 1) * options.chunk_size});
    total_bytes += options.chunk_size;
  }
  work_queue.Shutdown();
  for (auto& t : workers) {
    t.get();
  }
  auto const elapsed = std::chrono::steady_clock::now() - download_start;
  return {total_bytes, duration_cast<microseconds>(elapsed)};
}

google::cloud::Status DeleteGroup(gcs::Client client,
                                  std::vector<gcs::ObjectMetadata> group) {
  google::cloud::Status final_status{};
  for (auto const& o : group) {
    auto status = client.DeleteObject(o.bucket(), o.name(),
                                      gcs::Generation(o.generation()));
    if (!status.ok()) {
      final_status = std::move(status);
      continue;
    }
  }
  return final_status;
}

void DeleteAllObjects(gcs::Client client, std::string const& bucket_name,
                      Options const& options, std::vector<std::string> const&) {
  using std::chrono::duration_cast;
  using std::chrono::milliseconds;

  auto const max_group_size =
      std::max(options.object_count / options.thread_count, 1);

  std::cout << "# Deleting test objects [" << max_group_size << "]\n";
  auto start = std::chrono::steady_clock::now();
  std::vector<std::future<google::cloud::Status>> tasks;
  std::vector<gcs::ObjectMetadata> group;
  for (auto&& o : client.ListObjects(bucket_name, gcs::Versions(true))) {
    group.emplace_back(std::move(o).value());
    if (group.size() >= static_cast<std::size_t>(max_group_size)) {
      tasks.emplace_back(std::async(std::launch::async, &DeleteGroup, client,
                                    std::move(group)));
      group = {};  // after a move, must assign to guarantee it is valid.
    }
  }
  if (!group.empty()) {
    tasks.emplace_back(
        std::async(std::launch::async, &DeleteGroup, client, std::move(group)));
  }
  int count = 0;
  for (auto& t : tasks) {
    auto status = t.get();
    if (!status.ok()) {
      std::cerr << "Error return task[" << count << "]: " << status << "\n";
    }
    ++count;
  }
  // We do not print the latency to delete the objects because we have another
  // benchmark to measure that.
  auto elapsed = std::chrono::steady_clock::now() - start;
  std::cout << "# Deleted in " << duration_cast<milliseconds>(elapsed).count()
            << "ms\n";
}

google::cloud::StatusOr<Options> ParseArgs(int argc, char* argv[]) {
  Options options;
  bool wants_help = false;
  bool wants_description = false;
  std::vector<gcs_bm::OptionDescriptor> desc{
      {"--help", "print usage information",
       [&wants_help](std::string const&) { wants_help = true; }},
      {"--description", "print benchmark description",
       [&wants_description](std::string const&) { wants_description = true; }},
      {"--project-id", "use the given project id for the benchmark",
       [&options](std::string const& val) { options.project_id = val; }},
      {"--bucket-prefix", "configure the bucket's prefix",
       [&options](std::string const& val) { options.bucket_prefix = val; }},
      {"--region", "use the given region for the benchmark",
       [&options](std::string const& val) { options.region = val; }},
      {"--object-count", "set the number of objects created by the benchmark",
       [&options](std::string const& val) {
         options.object_count = std::stoi(val);
       }},
      {"--thread-count", "set the number of threads in the benchmark",
       [&options](std::string const& val) {
         options.thread_count = std::stoi(val);
       }},
      {"--iteration-size",
       "set the number of chunk downloaded in each iteration",
       [&options](std::string const& val) {
         options.iteration_size = std::stoi(val);
       }},
      {"--iteration-count",
       "set the number of samples captured by the benchmark",
       [&options](std::string const& val) {
         options.iteration_count = std::stoi(val);
       }},
      {"--chunk-size", "size of the chunks used in the benchmark",
       [&options](std::string const& val) {
         options.chunk_size = gcs_bm::ParseSize(val);
       }},
      {"--chunk-count", "the number of chunks in each object",
       [&options](std::string const& val) {
         options.chunk_count = std::stoi(val);
       }},
  };
  auto usage = gcs_bm::BuildUsage(desc, argv[0]);

  auto unparsed = gcs_bm::OptionsParse(desc, {argv, argv + argc});
  if (wants_help) {
    std::cout << usage << "\n";
  }

  if (wants_description) {
    std::cout << kDescription << "\n";
  }

  if (unparsed.size() > 2) {
    std::ostringstream os;
    os << "Unknown arguments or options\n" << usage << "\n";
    return google::cloud::Status{google::cloud::StatusCode::kInvalidArgument,
                                 std::move(os).str()};
  }
  if (unparsed.size() == 2) {
    options.region = unparsed[1];
  }
  if (options.region.empty()) {
    std::ostringstream os;
    os << "Missing value for --region option" << usage << "\n";
    return google::cloud::Status{google::cloud::StatusCode::kInvalidArgument,
                                 std::move(os).str()};
  }

  return options;
}

}  // namespace
