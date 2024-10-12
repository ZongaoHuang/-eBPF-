#include <dirent.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <regex>
#include <stdexcept>

#include "agent/container_manager.h"
#include "agent/process.h"
#include "agent/tcp.h"
#include "agent/tracker_manager.h"

using namespace std::chrono_literals;

int main(int argc, char** argv)
{
  {
    container_manager mp;
    tracker_manager manager;
    std::cout << "start ebpf...\n";

    // auto stdout_event_printer =
    //     std::make_shared<process_tracker::plain_text_event_printer>(process_tracker::plain_text_event_printer{});
    auto container_tracking_handler =
        std::make_shared<container_manager::container_tracking_handler>(container_manager::container_tracking_handler{ mp });
    auto container_process_handler =
        std::make_shared<container_manager::container_info_handler<process_event>>(container_manager::container_info_handler<process_event>{ mp });
    container_tracking_handler->add_handler(container_process_handler);

    // container_tracking_handler->add_handler(stdout_event_printer);
    auto stdout_event_printer =
         std::make_shared<tcp_tracker::plain_text_event_printer>(tcp_tracker::plain_text_event_printer{});
    auto container_info_handler =
        std::make_shared<container_manager::container_info_handler<tcp_event>>(container_manager::container_info_handler<tcp_event>{ mp });
    container_info_handler->add_handler(stdout_event_printer);

    manager.start_tracker(process_tracker::create_tracker_with_default_env(container_tracking_handler), "");
    manager.start_tracker(tcp_tracker::create_tracker_with_default_env(container_info_handler), "");

    std::this_thread::sleep_for(10s);
  }
  return 0;
}
