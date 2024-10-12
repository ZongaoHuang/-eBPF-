#include "agent/files.h"
#include "agent/process.h"
#include "agent/tracker_manager.h"

using namespace std::chrono_literals;

int main(int argc, char **argv)
{
  tracker_manager manager;
  container_manager mp;

  auto server = prometheus_server("127.0.0.1:8528", mp);
  std::cout << "start ebpf...\n";

  auto prometheus_process_handler =
      std::make_shared<process_tracker::prometheus_event_handler>(process_tracker::prometheus_event_handler(server));
  auto prometheus_files_handler =
      std::make_shared<files_tracker::prometheus_event_handler>(files_tracker::prometheus_event_handler(server));

  auto process_ptr = process_tracker::create_tracker_with_default_env(prometheus_process_handler);
  auto files_ptr = files_tracker::create_tracker_with_default_env(prometheus_files_handler);

  std::cout<< "start tracker..." << std::endl;
  manager.start_tracker(std::move(process_ptr), "");
  std::cout<< "start tracker..." << std::endl;
  manager.start_tracker(std::move(files_ptr), "");

  std::cout<< "start server..." << std::endl;
  server.start_prometheus_server();

  std::this_thread::sleep_for(10s);
  return 0;
}
