#include <string>

#include "agent/tracker_integrations.h"

extern "C"
{
#include "mountsnoop/mountsnoop_tracker.h"
}

std::unique_ptr<mountsnoop_tracker> mountsnoop_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "mountsnoop";
  config.env = tracker_alone_env{ .main_func = start_mountsnoop };
  return std::make_unique<mountsnoop_tracker>(config);
}

mountsnoop_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : agent_mountsnoop_counter(prometheus::BuildCounter()
                                     .Name("agent_observed_mountsnoop_counter")
                                     .Help("observed mount record")
                                     .Register(*server.registry)),
      container_manager_ref(server.core_container_manager_ref)
{
}

void mountsnoop_tracker::prometheus_event_handler::handle(tracker_event<tracker_alone_event> &e)
{
  thread_local static std::stringstream ss;
  std::string comm;
  int pid;
  int tid;
  std::string mnt_ns;
  std::string line;
  // get a line as data
  ss << e.data.process_messages;
  std::getline(ss, line);
  std::istringstream issline{ line };
  issline >> comm >> pid >> tid >> mnt_ns;
  // get container info from data
  auto container_info = container_manager_ref.get_container_info_for_pid(pid);
  agent_mountsnoop_counter
      .Add({
          { "comm", std::string(comm) },
          { "pid", std::to_string(pid) },
          { "tid", std::to_string(tid) },
      })
      .Increment(stoi(mnt_ns));
}

std::unique_ptr<mountsnoop_tracker> mountsnoop_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = mountsnoop_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
