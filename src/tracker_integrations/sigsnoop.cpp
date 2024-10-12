#include "agent/tracker_integrations.h"

extern "C"
{
#include "sigsnoop/sigsnoop_tracker.h"
}

std::unique_ptr<sigsnoop_tracker> sigsnoop_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "sigsnoop";
  config.env = tracker_alone_env{ .main_func = start_sigsnoop };
  return std::make_unique<sigsnoop_tracker>(config);
}

sigsnoop_tracker::prometheus_event_handler::prometheus_event_handler(prometheus_server &server)
    : agent_sigsnoop_counter(prometheus::BuildCounter()
                                   .Name("agent_observed_sigsnoop_counter")
                                   .Help("observed signals")
                                   .Register(*server.registry)),
      container_manager_ref(server.core_container_manager_ref)
{
}

void sigsnoop_tracker::prometheus_event_handler::handle(tracker_event<tracker_alone_event> &e)
{
  thread_local static std::stringstream ss;
  std::string time;
  std::string comm;
  int pid;
  int sig;
  int tpid;
  int result;
  std::string line;
  // get a line as data
  ss << e.data.process_messages;
  std::getline(ss, line);
  std::istringstream issline{ line };
  issline >> time >> pid >> comm >> sig >> tpid >> result;
  // get container info from data
  auto container_info = container_manager_ref.get_container_info_for_pid(pid);
  agent_sigsnoop_counter
      .Add({ { "task", comm },
             { "container_id", container_info.id },
             { "container_name", container_info.name },
             { "time", time },
             { "pid", std::to_string(pid) },
             { "signalId", std::to_string(sig) },
             { "tpid", std::to_string(tpid) },
             { "result", std::to_string(result) } })
      .Increment();
}

std::unique_ptr<sigsnoop_tracker> sigsnoop_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = sigsnoop_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
