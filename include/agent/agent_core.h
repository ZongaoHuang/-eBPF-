#ifndef AGENT_TRACKER_FACTORY_H
#define AGENT_TRACKER_FACTORY_H

#include <optional>

#include "config.h"
#include "agent/config.h"
#include "agent/container_manager.h"
#include "agent/files.h"
#include "agent/ipc.h"
#include "agent/myseccomp.h"
#include "agent/process.h"
#include "agent/prometheus_server.h"
#include "agent/sec_analyzer.h"
#include "agent/tcp.h"
#include "agent/tracker_manager.h"

/// core for building tracker

/// construct tracker with handlers
/// and manage state
struct agent_core
{
 private:
  /// agent config
  agent_config_data core_config;

  /// manager for all tracker
  tracker_manager core_tracker_manager;
  /// manager for container events
  container_manager core_container_manager;
  /// prometheus server
  prometheus_server core_prometheus_server;

  /// sec analyzer
  std::shared_ptr<sec_analyzer> core_sec_analyzer;

  /// create a event handlers for a tracker

  /// if the config is invalid, it will return a nullptr.
  template<tracker_concept TRACKER>
  TRACKER::tracker_event_handler create_tracker_event_handler(const handler_config_data& config);
  /// create all event handlers for a tracker
  template<tracker_concept TRACKER>
  TRACKER::tracker_event_handler create_tracker_event_handlers(const std::vector<handler_config_data>& handler_configs);

  /// create event handler for print to console
  template<tracker_concept TRACKER>
  TRACKER::tracker_event_handler create_print_event_handler(const TRACKER* tracker_ptr);

  template<tracker_concept TRACKER>
  std::unique_ptr<TRACKER> create_default_tracker(const tracker_config_data& base);

  /// create a default tracker with other handlers
  template<tracker_concept TRACKER>
  std::unique_ptr<TRACKER> create_default_tracker_with_handler(
      const tracker_config_data& base,
      TRACKER::tracker_event_handler);

  /// create a default tracker with sec_analyzer handlers
  template<tracker_concept TRACKER, typename SEC_ANALYZER_HANDLER>
  std::unique_ptr<TRACKER> create_default_tracker_with_sec_analyzer(const tracker_config_data& base);

  /// create process tracker with docker info
  std::unique_ptr<process_tracker> create_process_tracker_with_container_tracking(const tracker_config_data& base);

  /// start all trackers
  void start_trackers(void);
  /// check and stop all trackers if needed
  void check_auto_exit(void);
  /// start prometheus server
  void start_prometheus_server(void);
  /// start container manager
  void start_container_manager(void);
  /// start sec analyzer
  void start_sec_analyzer(void);

 public:
  agent_core(agent_config_data& config);
  /// start the core
  int start_agent(void);
  /// start a single tracker base on config
  std::optional<std::size_t> start_tracker(const tracker_config_data& config);
  /// list all trackers
  std::vector<std::tuple<int, std::string>> list_all_trackers(void);
  /// stop a tracker by id
  void stop_tracker(std::size_t tracker_id);
};

#endif
