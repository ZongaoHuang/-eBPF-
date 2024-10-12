#include "agent/tracker_integrations.h"

extern "C"
{
#include "capable/capable_tracker.h"
}

std::unique_ptr<capable_tracker> capable_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "capable";
  config.env = tracker_alone_env{ .main_func = start_capable };
  return std::make_unique<capable_tracker>(config);
}

capable_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : agent_capable_counter(prometheus::BuildCounter()
                                  .Name("agent_capable_counter")
                                  .Help("observed process capable")
                                  .Register(*server.registry)),
      container_manager_ref(server.core_container_manager_ref)
{
}

void capable_tracker::prometheus_event_handler::handle(tracker_event<tracker_alone_event> &e)
{
  thread_local static std::stringstream ss;
  std::string comm;
  std::string time;
  int pid;
  int uid;
  int cap;
  int audit;
  std::string name;
  std::string line;
  // get a line as data
  ss << e.data.process_messages;
  std::getline(ss, line);
  std::istringstream issline{ line };
  issline >> time >> uid >> pid >> comm >> cap >> name >> audit;
  // get container info from data
  auto container_info = container_manager_ref.get_container_info_for_pid(pid);
  agent_capable_counter
      .Add({ { "task", comm },
             { "container_id", container_info.id },
             { "container_name", container_info.name },
             { "pid", std::to_string(pid) },
             { "uid", std::to_string(uid) },
             { "cap", std::to_string(cap) },
             { "name", name },
             { "audit", std::to_string(audit) } })
      .Increment(pid);
}

std::unique_ptr<capable_tracker> capable_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = capable_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
