#include "agent/tracker_integrations.h"

extern "C"
{
#include "opensnoop/opensnoop_tracker.h"
}

std::unique_ptr<opensnoop_tracker> opensnoop_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "opensnoop";
  config.env = tracker_alone_env{ .main_func = start_opensnoop };
  return std::make_unique<opensnoop_tracker>(config);
}

opensnoop_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : agent_opensnoop_counter(prometheus::BuildCounter()
                                    .Name("agent_observed_open_counter")
                                    .Help("observed open syscall")
                                    .Register(*server.registry)),
      container_manager_ref(server.core_container_manager_ref)
{
}

void opensnoop_tracker::prometheus_event_handler::handle(tracker_event<tracker_alone_event> &e)
{
  thread_local static std::stringstream ss;
  std::string comm;
  int pid;
  int fd;
  int err;
  std::string path;
  std::string line;
  // get a line as data
  ss << e.data.process_messages;
  std::getline(ss, line);
  std::istringstream issline{ line };
  issline >> pid >> comm >> fd >> err >> path;
  // get container info from data
  auto container_info = container_manager_ref.get_container_info_for_pid(pid);
  agent_opensnoop_counter
      .Add({ { "task", comm },
             { "container_id", container_info.id },
             { "container_name", container_info.name },
             { "fd", std::to_string(fd) },
             { "err", std::to_string(err) },
             { "path", path } })
      .Increment(pid);
}

std::unique_ptr<opensnoop_tracker> opensnoop_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = opensnoop_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
