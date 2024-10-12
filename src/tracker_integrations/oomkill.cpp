#include "agent/tracker_integrations.h"

extern "C"
{
#include "oomkill/oom_tracker.h"
}

std::unique_ptr<oomkill_tracker> oomkill_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "oomkill";
  config.env = tracker_alone_env{ .main_func = start_oomkill };
  return std::make_unique<oomkill_tracker>(config);
}

std::unique_ptr<oomkill_tracker> oomkill_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = oomkill_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
