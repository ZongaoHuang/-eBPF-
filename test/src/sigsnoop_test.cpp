#include "agent/prometheus_server.h"
#include "agent/tracker_integrations.h"

//#include <gtest/gtest.h>

#include "agent/tracker_manager.h"

using namespace std::chrono_literals;

int main(int argc, char **argv)
{
  {
    tracker_manager manager;
    std::cout << "start ebpf...\n";

    auto test_event_printer =
        std::make_shared<sigsnoop_tracker::plain_text_event_printer>(sigsnoop_tracker::plain_text_event_printer{});

    auto tracker_ptr = sigsnoop_tracker::create_tracker_with_default_env(std::move(test_event_printer));
    manager.start_tracker(std::move(tracker_ptr), "");
    std::this_thread::sleep_for(10s);
  }
  return 0;
}
