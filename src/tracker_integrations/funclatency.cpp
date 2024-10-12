#include "agent/tracker_integrations.h"

extern "C"
{
#include "funclatency/funclatency_tracker.h"
}

std::unique_ptr<funclatency_tracker> funclatency_tracker::create_tracker_with_default_env(tracker_event_handler handler)
{
  config_data config;
  config.handler = handler;
  config.name = "funclatency";
  config.env = tracker_alone_env{ .main_func = start_funclatency };
  return std::make_unique<funclatency_tracker>(config);
}

std::unique_ptr<funclatency_tracker> funclatency_tracker::create_tracker_with_args(
    tracker_event_handler handler,
    const std::vector<std::string> &args)
{
  auto tracker = funclatency_tracker::create_tracker_with_default_env(handler);
  if (tracker)
  {
    tracker->current_config.env.process_args = args;
  }
  return tracker;
}
