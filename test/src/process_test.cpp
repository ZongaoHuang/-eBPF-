#include "agent/process.h"

//#include <gtest/gtest.h>

#include "agent/tracker_manager.h"

using namespace std::chrono_literals;

int main(int argc, char **argv)
{
  {
    tracker_manager manager;
    container_manager mp;
    std::cout << "start ebpf...\n";

    auto server = prometheus_server("127.0.0.1:8528", mp);

    auto prometheus_event_handler =
        std::make_shared<process_tracker::prometheus_event_handler>(process_tracker::prometheus_event_handler(server));
    auto json_event_printer = std::make_shared<process_tracker::json_event_printer>(process_tracker::json_event_printer{});
    prometheus_event_handler->add_handler(json_event_printer);

    auto tracker_ptr = process_tracker::create_tracker_with_default_env(json_event_printer);
    manager.start_tracker(std::move(tracker_ptr), "");

    server.start_prometheus_server();

    std::this_thread::sleep_for(10s);
  }
  return 0;
}
