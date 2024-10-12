#include "agent/files.h"

#include "agent/tracker_manager.h"

using namespace std::chrono_literals;

int main(int argc, char **argv)
{
  tracker_manager manager;
  container_manager mp;
  std::cout << "start ebpf...\n";

  auto server = prometheus_server("127.0.0.1:8528", mp);

  auto prometheus_event_handler =
      std::make_shared<files_tracker::prometheus_event_handler>(files_tracker::prometheus_event_handler(server));
  auto json_event_printer = std::make_shared<files_tracker::json_event_printer>(files_tracker::json_event_printer{});
  prometheus_event_handler->add_handler(json_event_printer);

  auto tracker_ptr = files_tracker::create_tracker_with_default_env(prometheus_event_handler);
  manager.start_tracker(std::move(tracker_ptr), "");

  server.start_prometheus_server();

  std::this_thread::sleep_for(10s);
  return 0;
}
