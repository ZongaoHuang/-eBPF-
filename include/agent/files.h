#ifndef FILE_CMD_H
#define FILE_CMD_H

#include <iostream>
#include <mutex>
#include <string>
#include <thread>

#include "libbpf_print.h"
#include "model/tracker.h"
#include "prometheus/counter.h"
#include "prometheus_server.h"
extern "C"
{
#include <files/file_tracker.h>
}

/// ebpf files tracker interface

/// the true implementation is in files/file_tracker.h
///
/// trace files read and write
struct files_tracker : public tracker_with_config<files_env, files_event>
{
  files_tracker(config_data config);

  /// create a tracker with deafult config
  static std::unique_ptr<files_tracker> create_tracker_with_default_env(tracker_event_handler handler);
  static std::unique_ptr<files_tracker> create_tracker_with_args(
      tracker_event_handler handler,
      const std::vector<std::string> &args)
  {
    return create_tracker_with_default_env(handler);
  }

  /// start files tracker
  void start_tracker();

  /// used for prometheus exporter
  struct prometheus_event_handler : public event_handler<files_event>
  {
    /// read times counter for field reads
    prometheus::Family<prometheus::Counter> &agent_files_read_counter;
    /// write times counter for field writes
    prometheus::Family<prometheus::Counter> &agent_files_write_counter;
    /// write bytes counter for field write_bytes
    prometheus::Family<prometheus::Counter> &agent_files_write_bytes;
    /// read bytes counter for field read_bytes
    prometheus::Family<prometheus::Counter> &agent_files_read_bytes;
    const container_manager &container_manager_ref;
    void report_prometheus_event(const struct files_event &e);

    prometheus_event_handler(prometheus_server &server);
    void handle(tracker_event<files_event> &e);
  };

  /// convert event to json
  struct json_event_handler : public event_handler<files_event>
  {
    std::string to_json(const struct files_event &e);
  };

  /// used for json exporter, inherits from json_event_handler
  struct json_event_printer : public json_event_handler
  {
    void handle(tracker_event<files_event> &e);
  };

  struct plain_text_event_printer : public event_handler<files_event>
  {
    void handle(tracker_event<files_event> &e);
  };

  struct csv_event_printer : public event_handler<files_event>
  {
    void handle(tracker_event<files_event> &e);
  };
};

#endif
