#ifndef SYSCALL_CMD_H
#define SYSCALL_CMD_H

#include <mutex>
#include <thread>

#include "libbpf_print.h"
#include "model/tracker.h"
#include "prometheus/counter.h"
#include "prometheus_server.h"

extern "C" {
#include <syscall/syscall_tracker.h>
#include "syscall_helper.h"
}

/// syscall tracker cpp interface

/// catch all syscall enter and exit events
class syscall_tracker : public tracker_with_config<syscall_env, syscall_event> {
public:
  syscall_tracker(config_data config);

  // create a tracker with deafult config
  static std::unique_ptr<syscall_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<syscall_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  void start_tracker();

  // used for prometheus exporter
  struct prometheus_event_handler : public event_handler<syscall_event>
  {
    // read times counter for field reads
    prometheus::Family<prometheus::Counter> &agent_files_syscall_counter;
    void report_prometheus_event(const struct syscall_event &e);

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<syscall_event> &e);
  };

  // convert event to json
  struct json_event_handler : public event_handler<syscall_event>
  {
    std::string to_json(const struct syscall_event &e);
  };

  // used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler
  {
    void handle(tracker_event<syscall_event> &e);
  };

  struct plain_text_event_printer : public event_handler<syscall_event>
  {
    void handle(tracker_event<syscall_event> &e);
  };

  struct csv_event_printer : public event_handler<syscall_event>
  {
    void handle(tracker_event<syscall_event> &e);
  };
};

#endif