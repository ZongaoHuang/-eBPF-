#include "agent/tracker_integrations.h"

extern "C"
{
#include "syscount/syscount_tracker.h"
}

std::unique_ptr<syscount_tracker> syscount_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "syscount";
  config.env = tracker_alone_env{ .main_func = start_syscount };
  return std::make_unique<syscount_tracker>(config);
}

std::unique_ptr<syscount_tracker> syscount_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = syscount_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
