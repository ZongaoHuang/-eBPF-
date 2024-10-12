#include "agent/tracker_integrations.h"

extern "C"
{
#include "bindsnoop/bindsnoop_tracker.h"
}

std::unique_ptr<bindsnoop_tracker> bindsnoop_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "bindsnoop";
  config.env = tracker_alone_env{ .main_func = start_bindsnoop };
  return std::make_unique<bindsnoop_tracker>(config);
}

bindsnoop_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : agent_bind_counter(prometheus::BuildCounter()
                               .Name("agent_observed_bind_counter")
                               .Help("observed open syscall")
                               .Register(*server.registry)),
      container_manager_ref(server.core_container_manager_ref)
{
}

void bindsnoop_tracker::prometheus_event_handler::handle(tracker_event<tracker_alone_event> &e)
{
  thread_local static std::stringstream ss;
  int pid;
  int ret;
  int IF;
  int port;
  std::string comm;
  std::string proto;
  std::string addr;
  std::string line;
  // get a line as data
  ss << e.data.process_messages;
  std::getline(ss, line);
  std::istringstream issline{ line };
  issline >> pid >> comm >> ret >> proto >> IF >> port >> addr;
  // get container info from data
  auto container_info = container_manager_ref.get_container_info_for_pid(pid);
  agent_bind_counter
      .Add({ { "task", comm },
             { "container_id", container_info.id },
             { "container_name", container_info.name },
             { "pid", std::to_string(pid) },
             { "ret", std::to_string(ret) },
             { "proto", proto },
             { "port", std::to_string(port) },
             { "addr", addr } })
      .Increment(pid);
}

std::unique_ptr<bindsnoop_tracker> bindsnoop_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = bindsnoop_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
