#include "agent/tracker_integrations.h"
#include "hot-update/update_tracker.h"

std::unique_ptr<hotupdate_tracker> hotupdate_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "updatable";
  config.env = tracker_alone_env{ .main_func = start_updatable };
  return std::make_unique<hotupdate_tracker>(config);
}

std::unique_ptr<hotupdate_tracker> hotupdate_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = hotupdate_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
